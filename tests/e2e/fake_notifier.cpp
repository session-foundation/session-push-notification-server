// A fake notifier: registers with the hivemind and records every notifier.push.
//
// usage: fake_notifier [--protocol N] [--max-body BYTES] [--stats] HIVEMIND_ADDR [MAX_QUEUE
//                      [SERVICE]]
//
// MAX_QUEUE is the oxenmq queue limit of the "notifier" category (default -1, unlimited); SERVICE
// is the service name it registers (default "dummy").  It registers speaking notifier protocol N
// (default 1; 0 sends the bare service name to the obsolete register_service), declaring BYTES as
// the largest body it can deliver (default 2500), and exits with status 2 if the hivemind refuses
// it or registering fails other than by timing out.  Answers notifier.validate by accepting
// service_info.token as the service id.  With --stats, it reports its stats (service_stats) once
// registered, as a real notifier does.  Prints "registered", then reads commands on stdin, one per
// line:
//
//   count    {"pushes": N, "unique": N, "duplicates": N, "first_ms": T, "last_ms": T}
//   dump     one line per push so far: "svcid hash ns body svcdata", body being the length of the
//            body pushed (0 for none), marked "!" if it is not the start of the body fake_network
//            makes for that hash, with " full=SIZE" after it for a message over the hivemind's body
//            limit; then "end"
//   quit
#include <oxenc/bt_producer.h>
#include <oxenc/bt_serialize.h>
#include <oxenmq/oxenmq.h>

#include <atomic>
#include <chrono>
#include <future>
#include <iostream>
#include <mutex>
#include <nlohmann/json.hpp>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

using namespace std::literals;

namespace {
int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
                   std::chrono::system_clock::now().time_since_epoch())
            .count();
}
}  // namespace

int main(int argc, char** argv) {
    int protocol = 1;
    int64_t max_body = 2500;
    bool stats = false;
    std::vector<std::string> args;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--protocol" && i + 1 < argc)
            protocol = std::stoi(argv[++i]);
        else if (a == "--max-body" && i + 1 < argc)
            max_body = std::stoll(argv[++i]);
        else if (a == "--stats")
            stats = true;
        else
            args.push_back(std::move(a));
    }
    if (args.empty()) {
        std::cerr << "usage: fake_notifier [--protocol N] [--max-body BYTES] [--stats] "
                     "HIVEMIND_ADDR [MAX_QUEUE [SERVICE]]\n";
        return 1;
    }
    // oxenmq's default: the hivemind's ack window must keep what it sends within it.
    int max_queue = args.size() > 1 ? std::stoi(args[1]) : 200;
    std::string service = args.size() > 2 ? args[2] : "dummy";

    std::mutex m;
    std::unordered_set<std::string> seen;
    std::vector<std::string> log;
    int64_t pushes = 0, duplicates = 0, first = 0, last = 0;

    oxenmq::OxenMQ omq;
    omq.add_category("notifier", oxenmq::AuthLevel::none, 0, max_queue)
            .add_command(
                    "push",
                    [&](oxenmq::Message& msg) {
                        oxenc::bt_dict_consumer d{msg.data.at(0)};
                        d.require<std::string_view>("");
                        auto svcdata = d.maybe<std::string_view>("!");
                        std::string hash{d.require<std::string_view>("#")};
                        std::string svcid{d.require<std::string_view>("&")};
                        d.skip_until("n");
                        auto ns = d.consume_integer<int>();
                        auto full_size = d.maybe<int64_t>("}");
                        auto body = d.maybe<std::string_view>("~");
                        bool intact = true;
                        if (body)
                            for (size_t k = 0; intact && k < body->size(); ++k)
                                intact = (*body)[k] == hash[k % hash.size()];

                        std::lock_guard lock{m};
                        auto t = now_ms();
                        if (pushes++ == 0)
                            first = t;
                        last = t;
                        if (!seen.insert(svcid + ' ' + hash).second)
                            duplicates++;
                        if (log.size() < 1000)
                            log.push_back(
                                    svcid + ' ' + hash + ' ' + std::to_string(ns) + ' ' +
                                    std::to_string(body ? body->size() : 0) + (intact ? "" : "!") +
                                    ' ' + (svcdata ? std::string{*svcdata} : "-") +
                                    (full_size ? " full=" + std::to_string(*full_size) : ""));
                    })
            .add_request_command("ack", [](oxenmq::Message& msg) { msg.send_reply(); })
            .add_request_command("validate", [](oxenmq::Message& msg) {
                auto info = nlohmann::json::parse(msg.data.at(1));
                msg.send_reply("0", info.at("token").get<std::string>());
            });
    omq.start();

    std::atomic<bool> connected{false};
    oxenmq::ConnectionID conn;
    for (int tries = 0; !connected && tries < 300; tries++) {
        std::promise<bool> p;
        conn = omq.connect_remote(
                oxenmq::address{args[0]},
                [&p](auto) { p.set_value(true); },
                [&p](auto, auto) { p.set_value(false); },
                oxenmq::AuthLevel::basic);
        connected = p.get_future().get();
        if (!connected)
            std::this_thread::sleep_for(200ms);
    }
    if (!connected) {
        std::cerr << "could not connect to " << args[0] << "\n";
        return 1;
    }
    if (protocol == 0)
        omq.send(conn, "admin.register_service", service);
    else {
        oxenc::bt_dict_producer reg;
        reg.append("", protocol);
        reg.append("max_body", max_body);
        // A request that times out is tried again, as a real notifier's periodic re-registration
        // would; a refusal, or any other failure, is final.
        while (true) {
            std::promise<std::pair<bool, std::vector<std::string>>> reply;
            omq.request(
                    conn,
                    "admin.register_notifier",
                    [&reply](bool ok, std::vector<std::string> data) {
                        reply.set_value({ok, std::move(data)});
                    },
                    service,
                    reg.view());
            auto [ok, data] = reply.get_future().get();
            if (!ok) {
                if (data.size() == 1 && data[0] == "TIMEOUT") {
                    std::cerr << "no reply to registration; retrying\n";
                    continue;
                }
                std::cerr << "registration failed:";
                for (const auto& d : data)
                    std::cerr << ' ' << d;
                std::cerr << "\n";
                return 2;
            }
            if (!data.empty() && !data[0].empty()) {
                std::cerr << "registration refused: " << data[0] << "\n";
                return 2;
            }
            break;
        }
    }
    if (stats) {
        oxenc::bt_dict_producer report;
        report.append("+failures", 0);
        report.append("+notifies", 0);
        omq.send(conn, "admin.service_stats", service, report.view());
    }
    std::cout << "registered" << std::endl;

    std::string line;
    while (std::getline(std::cin, line)) {
        std::lock_guard lock{m};
        if (line == "count")
            std::cout << nlohmann::
                                 json{{"pushes", pushes},
                                      {"unique", seen.size()},
                                      {"duplicates", duplicates},
                                      {"first_ms", first},
                                      {"last_ms", last}}
                                         .dump()
                      << std::endl;
        else if (line == "dump") {
            for (auto& l : log)
                std::cout << l << '\n';
            std::cout << "end" << std::endl;
        } else if (line == "quit")
            break;
    }
    return 0;
}
