#pragma once

#include <pqxx/connection>
#include <span>
#include <string_view>

namespace spns::schema {

// A one-time migration of the database (see spns/schema/README): its name, recorded in
// migrations_applied once it has run, and its SQL.
struct Migration {
    std::string_view name;
    std::string_view sql;
};

// The migrations in spns/schema, in the order they are applied, built in by CMake
// (cmake/SpnsSchema.cmake).
extern const std::span<const Migration> MIGRATIONS;

// spns/schema/full_schema.sql: the schema after every migration, which a new database is created
// from.
extern const std::string_view FULL_SCHEMA;

// Brings the database `conn` is connected to (in its current schema) up to date: creates it from
// FULL_SCHEMA if it has none of the migrations recorded and none of the hivemind's tables, and
// otherwise runs each migration not yet recorded, each in a transaction of its own.  Logs each
// migration applied, and nothing if none is needed.  Throws, naming the migration, if one fails,
// having rolled it back.
void apply_migrations(pqxx::connection& conn);

}  // namespace spns::schema
