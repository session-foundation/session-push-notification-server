# The end-to-end scenarios (see README.md).  Each `e2e-<scenario>` target builds the hivemind and
# the three fakes that e2e.py drives it with, and runs that scenario; `e2e-fast` and `e2e-slow`
# run their groups, and `e2e` runs everything.  The fakes are built only for these targets.
# Further options for e2e.py go through the E2E_ARGS environment variable, e.g.
#
#     make e2e-burst E2E_ARGS="--db other_db"

foreach(fake fake_network fake_notifier fake_client)
    add_executable(${fake} EXCLUDE_FROM_ALL ${fake}.cpp)
    target_link_libraries(${fake} PRIVATE
        PkgConfig::LIBQUIC
        PkgConfig::OXENMQ
        PkgConfig::OXENC
        PkgConfig::SODIUM
        PkgConfig::FMT
        PkgConfig::OXENLOGGING
        PkgConfig::NLOHMANN_JSON)
endforeach()

# A sanitized build runs several times slower, and under TSan needs address randomisation off; the
# harness handles both when told which sanitizer the build has.
set(e2e_sanitizer "")
foreach(san thread address)
    if(CMAKE_CXX_FLAGS MATCHES "-fsanitize=${san}")
        set(e2e_sanitizer --sanitizer ${san})
    endif()
endforeach()

# These lists must match FAST and SLOW in e2e.py, which rejects a name it does not know.
set(e2e_fast correctness burst resend notifier_restart two_notifiers backlog churn shutdown)
set(e2e_slow stalled_notifier sustained scale)

# Scenarios share ports and the database, so each target runs them in one e2e.py invocation rather
# than depending on the per-scenario targets, which a parallel build would run at once.
function(e2e_target name)
    string(JOIN " " scenarios ${ARGN})
    add_custom_target(${name}
        COMMAND sh -c "exec \"$0\" -u \"$1\" --build-dir \"$2\" $3 $E2E_ARGS ${scenarios}"
            "${Python_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/e2e.py" "${CMAKE_BINARY_DIR}"
            "${e2e_sanitizer}"
        DEPENDS spns spns_hivemind fake_network fake_notifier fake_client
        USES_TERMINAL
        VERBATIM)
endfunction()

foreach(scenario ${e2e_fast} ${e2e_slow})
    e2e_target(e2e-${scenario} ${scenario})
endforeach()
e2e_target(e2e-fast ${e2e_fast})
e2e_target(e2e-slow ${e2e_slow})
e2e_target(e2e ${e2e_fast} ${e2e_slow})
