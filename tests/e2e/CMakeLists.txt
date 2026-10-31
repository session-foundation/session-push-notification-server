cmake_minimum_required(VERSION 3.20)

# The fake network, notifier and client that tests/e2e/e2e.py drives the hivemind with.  Built
# separately from the main project, inside the container that tests/e2e/run.sh starts.
project(spns-e2e CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(DEPS REQUIRED IMPORTED_TARGET
    liboxenquic liboxenmq liboxenc libsodium fmt liboxen-logging nlohmann_json libzmq)

foreach(fake fake_network fake_notifier fake_client)
    add_executable(${fake} ${fake}.cpp)
    target_link_libraries(${fake} PRIVATE PkgConfig::DEPS)
endforeach()
