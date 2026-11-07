// usage: migrate_schema PG_CONNECT
//
// Brings the database PG_CONNECT names (a libpq connection string or URL; its search_path chooses
// the schema) up to date as the hivemind does at startup (see spns/migrations.hpp), logging what
// it applies to stderr, for e2e.py to make the hivemind's tables without starting one.

#include <fmt/core.h>

#include <oxen/log.hpp>
#include <pqxx/pqxx>

#include "migrations.hpp"

int main(int argc, char** argv) {
    if (argc != 2) {
        fmt::print(stderr, "usage: {} PG_CONNECT\n", argv[0]);
        return 2;
    }
    oxen::log::add_sink(oxen::log::Type::Print, "stderr");
    try {
        pqxx::connection conn{argv[1]};
        spns::schema::apply_migrations(conn);
    } catch (const std::exception& e) {
        fmt::print(stderr, "{}\n", e.what());
        return 1;
    }
    return 0;
}
