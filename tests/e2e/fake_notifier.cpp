// A fake notifier: registers with the hivemind and records every notifier.push.
//
// usage: fake_notifier HIVEMIND_ADDR [MAX_QUEUE [SERVICE]]
//
// MAX_QUEUE is the oxenmq queue limit of the "notifier" category (default -1, unlimited); SERVICE
// is the service name it registers (default "dummy").  Answers
// notifier.validate by accepting service_info.token as the service id.  Prints "registered", then
// reads commands on stdin, one per line:
//
//   count    {"pushes": N, "unique": N, "duplicates": N, "first_ms": T, "last_ms": T}
//   dump     one line per push so far: "svcid hash ns has_data svcdata", then "end"
//   quit
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
    if (argc < 2) {
        std::cerr << "usage: fake_notifier HIVEMIND_ADDR [MAX_QUEUE [SERVICE]]\n";
        return 1;
    }
    int max_queue = argc > 2 ? std::stoi(argv[2]) : -1;
    std::string service = argc > 3 ? argv[3] : "dummy";

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
                        bool data = d.skip_until("~");

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
                                    (data ? "1" : "0") + ' ' +
                                    (svcdata ? std::string{*svcdata} : "-"));
                    })
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
                oxenmq::address{argv[1]},
                [&p](auto) { p.set_value(true); },
                [&p](auto, auto) { p.set_value(false); },
                oxenmq::AuthLevel::basic);
        connected = p.get_future().get();
        if (!connected)
            std::this_thread::sleep_for(200ms);
    }
    if (!connected) {
        std::cerr << "could not connect to " << argv[1] << "\n";
        return 1;
    }
    omq.send(conn, "admin.register_service", service);
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
