#include <pybind11/pybind11.h>
#include <pybind11/pytypes.h>
#include <pybind11/stl.h>

#include <memory>
#include <oxen/log.hpp>
#include <oxen/log/level.hpp>

#include "bytes.hpp"
#include "config.hpp"
#include "hive/subscription.hpp"
#include "hivemind.hpp"

namespace py = pybind11;
using namespace py::literals;

struct HiveMindController {
    std::unique_ptr<spns::HiveMind> hivemind;

    HiveMindController(spns::Config conf) : hivemind{new spns::HiveMind{std::move(conf)}} {}

    void stop() { hivemind.reset(); }
};

namespace pybind11::detail {
template <spns::bytes_derived T>
struct type_caster<T> {

    PYBIND11_TYPE_CASTER(T, const_name("bytes") + const_name<T::SIZE>());

    bool load(handle src, bool) {
        if (py::isinstance<py::bytes>(src)) {
            auto sv = py::cast<py::bytes>(src).operator std::string_view();
            if (sv.size() == T::SIZE) {
                std::memcpy(value.data(), sv.data(), T::SIZE);
                return true;
            }
        }
        return false;
    }

    static handle cast(const T& src, return_value_policy /* policy */, handle /* parent */) {
        return py::bytes(reinterpret_cast<const char*>(src.data()), src.size());
    }
};

template <>
struct type_caster<oxen::quic::Address> {
    PYBIND11_TYPE_CASTER(oxen::quic::Address, const_name("quic_address"));

    bool load(handle src, bool) {
        if (py::isinstance<py::str>(src)) {
            value = oxen::quic::Address::parse(py::cast<std::string>(src));
            if (value.is_ipv6() && value.is_any_addr())
                value.dual_stack = true;
            return true;
        }
        return false;
    }

    static handle cast(
            const oxen::quic::Address& src, return_value_policy /* policy */, handle /* parent */) {
        return py::str(fmt::format(
                "{}{}{}:{}",
                src.is_ipv6() ? "[" : "",
                src.host(),
                src.is_ipv6() ? "]" : "",
                src.port()));
    }
};
}  // namespace pybind11::detail

PYBIND11_MODULE(spns_hivemind, m) {

    using namespace spns;

    // Python is kind of a pain in the ass about destruction, so use a wrapper class around the
    // actual HiveMind that lets us explicitly destruct.
    py::class_<HiveMindController>{m, "HiveMind"}
            .def(py::init<Config>(),
                 "Construts and starts a new HiveMind instance.  The instance will continue to run "
                 "until `.stop()` is called.",
                 "config"_a)
            .def("stop", &HiveMindController::stop);

    py::class_<Config>{m, "Config"}
            .def(py::init<>())
            .def_property(
                    "oxend_rpc",
                    [](Config& self) { return self.oxend_rpc.full_address(); },
                    [](Config& self, std::string addr) {
                        self.oxend_rpc = oxenmq::address{std::move(addr)};
                    },
                    "oxenmq address of the companion oxend RPC to use")
            .def_readwrite("pg_connect", &Config::pg_connect, "postgresql connection URL")
            .def_readwrite(
                    "hivemind_sock", &Config::hivemind_sock, "local hivemind admin oxenmq socket")
            .def_readwrite(
                    "hivemind_curve",
                    &Config::hivemind_curve,
                    "optional secondary hivemind curve-enabled listening socket")
            .def_readwrite(
                    "hivemind_curve_admin",
                    &Config::hivemind_curve_admin,
                    "set of X25519 pubkeys recognized as admin for incoming `hivemind_curve` "
                    "connections")
            .def_readwrite(
                    "omq_pubkey",
                    &Config::omq_pubkey,
                    "X25519 server pubkey; must be set (the default value will not work)")
            .def_readwrite(
                    "omq_privkey",
                    &Config::omq_privkey,
                    "X25519 server privkey; must be set (the default value will not work)")
            .def_readwrite(
                    "quic_keys",
                    &Config::quic_keys,
                    "Ed25519 combined secret key + pubkey value (64 bytes), used for QUIC; must be "
                    "set (the default value will not work)")
            .def_readwrite(
                    "quic_listen", &Config::quic_listen, "Optional listen addresses for quic")
            .def_property(
                    "filter_lifetime",
                    [](Config& self) { return self.filter_lifetime.count(); },
                    [](Config& self, int64_t seconds) { self.filter_lifetime = 1s * seconds; },
                    "the notification replay filter lifetime, in seconds")
            .def_property(
                    "notifier_wait",
                    [](Config& self) { return self.notifier_wait.count(); },
                    [](Config& self, int64_t milliseconds) {
                        self.notifier_wait = 1ms * milliseconds;
                    },
                    "how long, in milliseconds, after initialization to wait for notifier servers "
                    "to register themselves with the HiveMind instance")
            .def_readwrite(
                    "notifiers_expected",
                    &Config::notifiers_expected,
                    "Set of notification services that we expect; if non-empty then we will stop "
                    "the `notifier_wait` time early once we have registered notifiers for all the "
                    "values set here.")
            .def_readwrite(
                    "monitor_body_limit",
                    &Config::monitor_body_limit,
                    "most bytes of a message body that reach a device, for subscriptions that want "
                    "data; a bigger message is pushed cut to this, with its full size, to "
                    "subscriptions that opted in to truncated bodies, and as its size alone to the "
                    "rest.  Must be positive; the default of 2500 is the most the push services "
                    "accept once the body is encrypted and encoded, and larger is only for testing.")
            .def_readwrite(
                    "redundancy",
                    &Config::redundancy,
                    "how many of its swarm's nodes each account is subscribed on, at most the "
                    "swarm's size: -1 for all of them, or a positive number")
            .def_readwrite(
                    "resume_replay",
                    &Config::resume_replay,
                    "most notifications per account a node replays when our monitor session with "
                    "it is resumed: the newest, the rest lost")
            .def_property(
                    "renewal_interval",
                    [](Config& self) -> std::optional<int64_t> {
                        if (self.renewal_interval)
                            return self.renewal_interval->count();
                        return std::nullopt;
                    },
                    [](Config& self, std::optional<int64_t> secs) {
                        if (secs)
                            self.renewal_interval = std::chrono::seconds{*secs};
                        else
                            self.renewal_interval.reset();
                    },
                    "seconds between an account's renewals, if not 45-55 minutes: for testing; "
                    "None for the default")
            .def_readwrite(
                    "monitor_requests",
                    &Config::monitor_requests,
                    "most monitor requests in flight at once across all nodes; must be positive")
            .def_property(
                    "monitor_timeout",
                    [](Config& self) {
                        return std::chrono::duration<double>(self.monitor_timeout).count();
                    },
                    [](Config& self, double seconds) {
                        self.monitor_timeout =
                                std::chrono::milliseconds{static_cast<int64_t>(seconds * 1000)};
                    },
                    "seconds a monitor request may go unanswered before it counts as failed; must "
                    "be positive")
            .def_property(
                    "status_report_interval",
                    [](Config& self) { return self.status_report_interval.count(); },
                    [](Config& self, int64_t seconds) {
                        self.status_report_interval = std::chrono::seconds{seconds};
                    },
                    "seconds between status reports in the log; at least 2")
            .def_readwrite(
                    "status_report_file",
                    &Config::status_report_file,
                    "file each status report is written to as well, as Markdown; empty for none")
            .def_readwrite(
                    "max_pending_connects",
                    &Config::max_pending_connects,
                    "maximum number of permitted simultaneous connection attempts.  (This is not "
                    "the number of simultaneous connections, just how many we new connections we "
                    "will attempt at once");

    class Logger {};
    py::class_<Logger>{m, "logger"}
            .def_static(
                    "set_level",
                    [](std::string_view cat_levels) { oxen::log::apply_categories(cat_levels); },
                    "Sets/resets the log level; can be a global level (e.g. 'info') or individual "
                    "'cat=debug' level values")
            //
            ;

    static_assert(
            static_cast<int>(hive::SUBSCRIBE::_END) == 6,
            "pybind11 binding is missing SUBSCRIBE enum elements");

    py::enum_<hive::SUBSCRIBE>{m, "SUBSCRIBE"}
            .value("OK", hive::SUBSCRIBE::OK)
            .value("BAD_INPUT", hive::SUBSCRIBE::BAD_INPUT)
            .value("SERVICE_NOT_AVAILABLE", hive::SUBSCRIBE::SERVICE_NOT_AVAILABLE)
            .value("SERVICE_TIMEOUT", hive::SUBSCRIBE::SERVICE_TIMEOUT)
            .value("ERROR", hive::SUBSCRIBE::ERROR)
            .value("INTERNAL_ERROR", hive::SUBSCRIBE::INTERNAL_ERROR)
            .export_values();
}
