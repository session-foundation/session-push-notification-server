# Builds a directory of database migrations into a target, so that the hivemind needs none of the
# files at run time (see spns/schema/README):
#
#   spns_schema_dir(
#       TARGET <target>            # target the generated registry is compiled into
#       DIR <dir>                  # directory of NNN_description.sql migrations and full_schema.sql
#       DECLARE_HEADER <header>    # absolute path of the header declaring spns::schema::MIGRATIONS
#                                  # and FULL_SCHEMA, which the generated definitions include, so
#                                  # that the two cannot drift apart
#   )

set(SPNS_SCHEMA_TEMPLATE "${CMAKE_CURRENT_LIST_DIR}/schema_registry.cpp.in")

function(spns_schema_dir)
    cmake_parse_arguments(PARSE_ARGV 0 SCHEMA "" "TARGET;DIR;DECLARE_HEADER" "")

    foreach(required TARGET DIR DECLARE_HEADER)
        if(NOT SCHEMA_${required})
            message(FATAL_ERROR "spns_schema_dir: ${required} is required")
        endif()
    endforeach()

    # Watch the directory, so that adding or removing a migration re-runs CMake:
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${SCHEMA_DIR}")

    file(GLOB SCHEMA_FILES "${SCHEMA_DIR}/[0-9]*.sql")

    # Order migrations by the name recorded in migrations_applied, not by filename: the extension
    # is not part of a migration's identity, and including it flips the order whenever one name is
    # a prefix of another, since "001_foo+002.sql" sorts before "001_foo.sql" ('+' is 0x2B, '.' is
    # 0x2E).
    #
    # Decorate, sort, undecorate.  The separator has to sort below every character a name can
    # contain or the prefix case breaks again one level down, so it is a control character rather
    # than any punctuation.
    string(ASCII 1 SCHEMA_SEP)
    list(TRANSFORM SCHEMA_FILES REPLACE "^(.*/)([^/]*)\\.sql$" "\\2${SCHEMA_SEP}\\1\\2.sql"
        OUTPUT_VARIABLE SCHEMA_DECORATED)
    list(SORT SCHEMA_DECORATED)
    list(TRANSFORM SCHEMA_DECORATED REPLACE "^[^${SCHEMA_SEP}]*${SCHEMA_SEP}" ""
        OUTPUT_VARIABLE SCHEMA_FILES)

    list(LENGTH SCHEMA_FILES SCHEMA_COUNT)

    # The SQL goes into raw string literals, which this would end early.
    set(SCHEMA_DELIM ")_SQL_DELIM_\"")
    set(SCHEMA_ENTRIES "")
    foreach(f IN LISTS SCHEMA_FILES)
        # Watch individual files, so that edits re-run CMake:
        set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${f}")
        get_filename_component(filename "${f}" NAME)
        string(REGEX REPLACE "\\.sql$" "" name "${filename}")
        file(READ "${f}" sql)
        string(FIND "${sql}" "${SCHEMA_DELIM}" found)
        if(NOT found EQUAL -1)
            message(FATAL_ERROR "spns_schema_dir: ${f} contains ${SCHEMA_DELIM}")
        endif()
        string(APPEND SCHEMA_ENTRIES "        {\"${name}\", R\"_SQL_DELIM_(${sql})_SQL_DELIM_\"},\n")
    endforeach()

    set(full_schema "${SCHEMA_DIR}/full_schema.sql")
    if(NOT EXISTS "${full_schema}")
        message(FATAL_ERROR "spns_schema_dir: ${full_schema} is missing")
    endif()
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${full_schema}")
    file(READ "${full_schema}" SCHEMA_FULL)
    string(FIND "${SCHEMA_FULL}" "${SCHEMA_DELIM}" found)
    if(NOT found EQUAL -1)
        message(FATAL_ERROR "spns_schema_dir: ${full_schema} contains ${SCHEMA_DELIM}")
    endif()

    file(RELATIVE_PATH SCHEMA_DIR_REL "${PROJECT_SOURCE_DIR}" "${SCHEMA_DIR}")
    set(registry "${CMAKE_CURRENT_BINARY_DIR}/spns_schema_registry.cpp")
    configure_file("${SPNS_SCHEMA_TEMPLATE}" "${registry}" @ONLY)
    target_sources(${SCHEMA_TARGET} PRIVATE "${registry}")
endfunction()
