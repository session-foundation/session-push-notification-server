
cmake_minimum_required(VERSION 3.18)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_program(CCACHE_PROGRAM ccache)
if(CCACHE_PROGRAM)
  foreach(lang C CXX)
    if(NOT DEFINED CMAKE_${lang}_COMPILER_LAUNCHER AND NOT CMAKE_${lang}_COMPILER MATCHES ".*/ccache")
      message(STATUS "Enabling ccache for ${lang}")
      set(CMAKE_${lang}_COMPILER_LAUNCHER ${CCACHE_PROGRAM} CACHE STRING "")
    endif()
  endforeach()
endif()

project(spns)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

add_library(spns STATIC
    spns/hivemind.cpp
    spns/pg.cpp
    spns/swarmpubkey.cpp
    spns/utils.cpp
    spns/hive/signature.cpp
    spns/hive/snode.cpp
    spns/hive/subscription.cpp
)

find_package(PkgConfig REQUIRED)

pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium>=1.0.18)
pkg_check_modules(OXENC REQUIRED IMPORTED_TARGET liboxenc>=1.4.0)
pkg_check_modules(OXENMQ REQUIRED IMPORTED_TARGET liboxenmq>=1.2.22)
pkg_check_modules(LIBQUIC REQUIRED IMPORTED_TARGET liboxenquic>=1.6)
pkg_check_modules(OXENLOGGING REQUIRED IMPORTED_TARGET liboxen-logging>=1.2.0)
pkg_check_modules(NLOHMANN_JSON REQUIRED IMPORTED_TARGET nlohmann_json>=3.7.0)
pkg_check_modules(SYSTEMD REQUIRED IMPORTED_TARGET libsystemd)

if(CMAKE_VERSION VERSION_LESS "3.21")
    # Work around cmake bug 22180 (PkgConfig::THING not set if no flags needed)
    add_library(_deps_dummy INTERFACE)
    foreach(pkg OXENC NLOHMANN_JSON)
        if(NOT TARGET PkgConfig::${pkg})
            add_library(PkgConfig::${pkg} ALIAS _deps_dummy)
        endif()
    endforeach()
endif()

include(cmake/submodule_check.cmake)
include(cmake/system_or_submodule.cmake)

system_or_submodule(LIBPQXX libpqxx libpqxx::pqxx libpqxx>=8 libpqxx)

target_link_libraries(spns PRIVATE
    PkgConfig::SODIUM
    PkgConfig::OXENC
    PkgConfig::OXENMQ
    PkgConfig::LIBQUIC
    PkgConfig::OXENLOGGING
    PkgConfig::NLOHMANN_JSON
    PkgConfig::SYSTEMD
    PUBLIC
    libpqxx::pqxx)

set_target_properties(spns PROPERTIES INTERPROCEDURAL_OPTIMIZATION ON)

set(PYBIND11_FINDPYTHON ON CACHE INTERNAL "")
add_subdirectory(pybind11)
pybind11_add_module(
    core
    spns/pybind.cpp)

target_link_libraries(core PUBLIC spns)
set_target_properties(core PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/spns)
