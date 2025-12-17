#include <pthread.h>
#include <pybind11/embed.h>
#include <pybind11/pytypes.h>

#include <csignal>
#include <oxen/log.hpp>

#include "config.hpp"
#include "hivemind.hpp"

using namespace std::literals;
namespace py = pybind11;

auto cat = oxen::log::Cat("spns");

int usage(std::string_view argv0, std::string_view err = ""sv) {
    if (!err.empty())
        oxen::log::error(cat, "Error: {}\n", err);

    oxen::log::error(cat, "Usage: {} /path/to/spns.ini\n", argv0);
    return 1;
}

int main(int argc, char** argv) {

    namespace log = oxen::log;
    log::add_sink(oxen::log::Type::Print, "stderr");

    sigset_t sigset;
    sigemptyset(&sigset);
    sigaddset(&sigset, SIGINT);
    sigaddset(&sigset, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &sigset, nullptr);

    if (argc != 2 || argv[1] == "-h"sv || argv[1] == "--help"sv)
        return usage(argv[0]);

    std::string_view ini{argv[1]};

    log::info(cat, "Loading config from {}", ini);

    spns::Config conf;
    try {
        py::scoped_interpreter interp{};
        try {
            auto mconf = py::module_::import("spns.conf");
            conf = std::move(mconf.attr("load_config")(ini).cast<spns::Config&>());
        } catch (const pybind11::error_already_set& e) {
            // Rewrap the exception because calling `e.what()` on this requires an active python
            // interpreter, which we won't have when we leave the other `try {}`.
            throw std::runtime_error{e.what()};
        }
    } catch (const pybind11::error_already_set&) {
        log::critical(cat, "Failed to load python interpreter");
        return 2;
    } catch (const std::exception& e) {
        log::critical(
                cat, "Failed to load configuration file {}: {}", ini, e.what());
        return 1;
    }

    log::info(cat, "Initializing hivemind");
    spns::HiveMind hivemind{std::move(conf)};
    log::info(cat, "Hivemind started");

    // We don't need any signal handler: when a SIGINT/SIGTERM comes in we just catch it here, stop
    // waiting, and thus roll off the end of the main() function, which destroys the HiveMind
    // instance which shuts everything down.
    int sig;
    sigwait(&sigset, &sig);
    log::warning(cat, "Received signal {}; shutting down", sig);

    return 0;
}
