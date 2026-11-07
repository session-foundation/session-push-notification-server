#include "migrations.hpp"

#include <fmt/core.h>

#include <algorithm>
#include <oxen/log.hpp>
#include <pqxx/pqxx>
#include <stdexcept>
#include <string>
#include <unordered_set>

namespace spns::schema {

namespace log = oxen::log;
static auto cat = log::Cat("schema");

// Held by each step, so that hiveminds starting together on one database take turns, each seeing
// what the one before it committed.  ("SPNS" in ASCII, then 1.)
constexpr int64_t MIGRATION_LOCK = 0x53504E53'00000001;

static void lock(pqxx::work& tx) {
    tx.exec("SELECT pg_advisory_xact_lock($1)", pqxx::params{MIGRATION_LOCK}).one_row();
}

void apply_migrations(pqxx::connection& conn) {
    {
        pqxx::work tx{conn};
        lock(tx);
        tx.exec(R"(
CREATE TABLE IF NOT EXISTS migrations_applied (
    name TEXT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
))")
                .no_rows();

        std::unordered_set<std::string> applied;
        for (auto [name] : tx.query<std::string>("SELECT name FROM migrations_applied"))
            applied.insert(std::move(name));

        // A database with tables but nothing recorded predates the recording, and is brought level
        // by the migrations, the first of which are written for it (see spns/schema/README).
        if (std::ranges::none_of(MIGRATIONS, [&](const auto& m) {
                return applied.contains(std::string{m.name});
            })) {
            auto [tables] = tx.query1<int64_t>(
                    "SELECT count(*) FROM pg_tables WHERE schemaname = current_schema() AND "
                    "tablename <> 'migrations_applied'");
            if (tables == 0) {
                try {
                    tx.exec(FULL_SCHEMA);
                    for (const auto& m : MIGRATIONS)
                        tx.exec("INSERT INTO migrations_applied (name) VALUES ($1)",
                                pqxx::params{m.name})
                                .no_rows();
                    tx.commit();
                } catch (const std::exception& e) {
                    throw std::runtime_error{
                            fmt::format("creating the database schema failed: {}", e.what())};
                }
                log::info(
                        cat,
                        "Created the database schema, at migration {}",
                        MIGRATIONS.empty() ? "(none)" : MIGRATIONS.back().name);
                return;
            }
        }
        tx.commit();
    }

    for (const auto& m : MIGRATIONS) {
        pqxx::work tx{conn};
        lock(tx);
        if (tx.query01<int>(
                    "SELECT 1 FROM migrations_applied WHERE name = $1", pqxx::params{m.name}))
            continue;
        try {
            tx.exec(m.sql);
            tx.exec("INSERT INTO migrations_applied (name) VALUES ($1)", pqxx::params{m.name})
                    .no_rows();
            tx.commit();
        } catch (const std::exception& e) {
            throw std::runtime_error{
                    fmt::format("database migration {} failed: {}", m.name, e.what())};
        }
        log::info(cat, "Applied database migration {}", m.name);
    }
}

}  // namespace spns::schema
