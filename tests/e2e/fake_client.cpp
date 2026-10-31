// Subscribes and unsubscribes signed 05 accounts through the hivemind's push.subscribe and
// push.unsubscribe, and drops registrations through admin.drop_registrations.
//
// usage: fake_client HIVEMIND_ADDR
//
// Client account i has the Ed25519 key seeded by SHA256("spns-e2e-client" || i) and the service id
// "client-i-" padded to 40 characters.  Reads commands on stdin, one per line, answering each with
// one line:
//
//   account I               the account id of client I, in hex
//   sub I                   subscribe client I to namespace 0, with data
//   unsub I                 unsubscribe client I
//   drop SVCID              drop the "dummy" registration SVCID
//   churn FIRST COUNT ROUNDS
//                           ROUNDS times, subscribe clients FIRST.. then unsubscribe them, each
//                           step's requests in flight together; then subscribe the even ones.
//                           Answers "ok SUBS UNSUBS FAILURES".
//   quit
#include <oxenc/bt_producer.h>
#include <oxenc/hex.h>
#include <oxenmq/oxenmq.h>
#include <sodium.h>

#include <atomic>
#include <chrono>
#include <future>
#include <iostream>
#include <nlohmann/json.hpp>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

using namespace std::literals;

namespace {

struct Client {
    unsigned char pk[32], sk[64];
    std::string account_hex, svcid;

    explicit Client(int i) {
        unsigned char seed[32];
        std::string s = "spns-e2e-client" + std::to_string(i);
        crypto_hash_sha256(seed, reinterpret_cast<const unsigned char*>(s.data()), s.size());
        crypto_sign_seed_keypair(pk, sk, seed);
        unsigned char x[32];
        if (crypto_sign_ed25519_pk_to_curve25519(x, pk) != 0)
            throw std::runtime_error{"ed25519 to x25519 conversion failed"};
        account_hex = "05" + oxenc::to_hex(x, x + 32);
        svcid = "client-" + std::to_string(i) + "-";
        svcid.resize(40, 'a');
    }

    std::string sign(const std::string& msg) const {
        unsigned char sig[64];
        crypto_sign_detached(
                sig, nullptr, reinterpret_cast<const unsigned char*>(msg.data()), msg.size(), sk);
        return oxenc::to_hex(sig, sig + 64);
    }

    nlohmann::json base(int64_t ts) const {
        return {{"pubkey", account_hex},
                {"session_ed25519", oxenc::to_hex(pk, pk + 32)},
                {"sig_ts", ts},
                {"service", "dummy"},
                {"service_info", {{"token", svcid}}}};
    }

    std::string subscribe_body(int64_t ts) const {
        auto j = base(ts);
        j["namespaces"] = {0};
        j["data"] = true;
        j["enc_key"] = std::string(64, 'e');
        j["signature"] = sign("MONITOR" + account_hex + std::to_string(ts) + "1" + "0");
        return j.dump();
    }

    std::string unsubscribe_body(int64_t ts) const {
        auto j = base(ts);
        j["signature"] = sign("UNSUBSCRIBE" + account_hex + std::to_string(ts));
        return j.dump();
    }
};

int64_t now_s() {
    return std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch())
            .count();
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 2 || sodium_init() < 0) {
        std::cerr << "usage: fake_client HIVEMIND_ADDR\n";
        return 1;
    }
    oxenmq::OxenMQ omq;
    omq.start();
    auto conn = omq.connect_remote(
            oxenmq::address{argv[1]}, [](auto) {}, [](auto, auto) {}, oxenmq::AuthLevel::admin);

    // Sends one request per (command, body) at once and waits for all of them; returns how many
    // replies carried "success".
    auto requests = [&](const std::vector<std::pair<std::string, std::string>>& reqs) {
        std::atomic<int> ok{0}, pending{(int)reqs.size()};
        std::promise<void> done;
        if (reqs.empty())
            return 0;
        for (auto& [cmd, body] : reqs)
            omq.request(
                    conn,
                    cmd,
                    [&](bool success, std::vector<std::string> data) {
                        if (success && !data.empty() &&
                            nlohmann::json::parse(data[0]).value("success", false))
                            ok++;
                        if (--pending == 0)
                            done.set_value();
                    },
                    body,
                    oxenmq::send_option::request_timeout{60s});
        done.get_future().wait();
        return ok.load();
    };

    std::string line;
    while (std::getline(std::cin, line)) {
        std::istringstream in{line};
        std::string cmd;
        in >> cmd;
        if (cmd == "account") {
            int i;
            in >> i;
            std::cout << Client{i}.account_hex << std::endl;
        } else if (cmd == "sub" || cmd == "unsub") {
            int i;
            in >> i;
            Client c{i};
            bool sub = cmd == "sub";
            int ok = requests(
                    {{sub ? "push.subscribe" : "push.unsubscribe",
                      sub ? c.subscribe_body(now_s()) : c.unsubscribe_body(now_s())}});
            std::cout << (ok ? "ok" : "failed") << std::endl;
        } else if (cmd == "drop") {
            std::string svcid;
            in >> svcid;
            oxenc::bt_list_producer drops;
            drops.append(svcid);
            omq.send(conn, "admin.drop_registrations", "dummy", std::move(drops).str());
            std::cout << "ok" << std::endl;
        } else if (cmd == "churn") {
            int first, count, rounds;
            in >> first >> count >> rounds;
            std::vector<Client> clients;
            for (int i = first; i < first + count; i++)
                clients.emplace_back(i);
            int subs = 0, unsubs = 0, wanted = 0;
            auto step = [&](bool sub, bool evens_only) {
                std::vector<std::pair<std::string, std::string>> reqs;
                auto ts = now_s();
                for (int k = 0; k < count; k++)
                    if (!evens_only || (first + k) % 2 == 0)
                        reqs.emplace_back(
                                sub ? "push.subscribe" : "push.unsubscribe",
                                sub ? clients[k].subscribe_body(ts)
                                    : clients[k].unsubscribe_body(ts));
                wanted += reqs.size();
                return requests(reqs);
            };
            for (int r = 0; r < rounds; r++) {
                subs += step(true, false);
                unsubs += step(false, false);
            }
            subs += step(true, true);
            std::cout << "ok " << subs << ' ' << unsubs << ' ' << (wanted - subs - unsubs)
                      << std::endl;
        } else if (cmd == "quit") {
            break;
        } else {
            std::cout << "error unknown command " << cmd << std::endl;
        }
    }
    return 0;
}
