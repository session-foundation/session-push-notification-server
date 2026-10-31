// A fake oxend and a fake swarm of storage nodes for driving the hivemind end to end.
//
// usage: fake_network NODES SWARMS OXEND_PORT FIRST_QUIC_PORT
//
// oxend: oxenmq on tcp://127.0.0.1:OXEND_PORT answering ping.ping and rpc.get_service_nodes with
// NODES nodes spread over SWARMS swarms, so that the hivemind subscribes each account on one
// swarm's nodes only.  Storage nodes: libquic on 127.0.0.1:FIRST_QUIC_PORT+i, answering "monitor"
// with success.  Every notification is sent by each of the first SENDERS nodes (default: all), as
// every member of a real swarm would; the hivemind does not check which node sends one.
//
// Prints "ready" once every node has a stream from the hivemind, then reads commands on stdin, one
// per line, and answers each with one line:
//
//   send ACCOUNT HASH NS BODY_BYTES     one notification (ACCOUNT: 66 hex digits or #index)
//   burst FIRST COUNT ACCOUNTS NS BODY  COUNT notifications for messages FIRST.., spread over
//                                       accounts #0..ACCOUNTS-1; BODY is a size, or "mix"
//   rate PER_SEC SECONDS ACCOUNTS NS BODY FIRST
//                                       like burst, paced at PER_SEC for SECONDS (blocks)
//   senders N                           send from the first N nodes only
//   backlog                             largest unsent + unacked bytes on any node's stream since
//                                       the last backlog command, sampled every 20ms
//   quit
//
// Account #i is 03 || SHA256(big-endian 32-bit i), the same bytes e2e.py seeds the database with.
#include <oxenc/bt_producer.h>
#include <oxenc/bt_serialize.h>
#include <oxenc/hex.h>
#include <oxenmq/oxenmq.h>
#include <sodium.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <iostream>
#include <mutex>
#include <nlohmann/json.hpp>
#include <oxen/quic.hpp>
#include <oxen/quic/btstream.hpp>
#include <oxen/quic/gnutls_crypto.hpp>
#include <sstream>
#include <thread>
#include <vector>

namespace quic = oxen::quic;
using namespace std::literals;

namespace {

int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
                   std::chrono::system_clock::now().time_since_epoch())
            .count();
}

std::string indexed_account(uint32_t i) {
    unsigned char be[4] = {
            (unsigned char)(i >> 24),
            (unsigned char)(i >> 16),
            (unsigned char)(i >> 8),
            (unsigned char)i};
    std::string a(33, '\0');
    a[0] = 0x03;
    crypto_hash_sha256(reinterpret_cast<unsigned char*>(a.data() + 1), be, 4);
    return a;
}

std::string parse_account(const std::string& s) {
    if (!s.empty() && s[0] == '#')
        return indexed_account(std::stoul(s.substr(1)));
    return oxenc::from_hex(s);
}

std::string message_hash(uint64_t n) {
    char h[48];
    std::snprintf(h, sizeof h, "msg-%039llu", (unsigned long long)n);
    return h;
}

// "mix" is mostly small bodies with an occasional storage-server-maximum one.
size_t body_size(const std::string& spec, uint64_t n) {
    if (spec != "mix")
        return std::stoul(spec);
    if (n % 50 == 0)
        return 76'800;
    return 500 + (n * 7919) % 4500;
}

std::string notification(const std::string& account, const std::string& hash, int ns, size_t body) {
    oxenc::bt_dict_producer d;
    d.append("@", account);
    d.append("h", hash);
    d.append("n", ns);
    d.append("t", now_ms());
    d.append("z", now_ms() + 14 * 86400 * 1000LL);
    if (body)
        d.append("~", std::string(body, 'x'));
    return std::move(d).str();
}

struct Node {
    std::string pk, sk;
    std::shared_ptr<quic::Endpoint> ep;
    std::shared_ptr<quic::BTRequestStream> stream;
};

}  // namespace

int main(int argc, char** argv) {
    if (argc != 5 || sodium_init() < 0) {
        std::cerr << "usage: fake_network NODES SWARMS OXEND_PORT FIRST_QUIC_PORT\n";
        return 1;
    }
    int n_nodes = std::stoi(argv[1]);
    uint64_t n_swarms = std::stoul(argv[2]);
    int oxend_port = std::stoi(argv[3]);
    int first_port = std::stoi(argv[4]);
    std::atomic<int> senders{n_nodes};

    quic::Loop loop;
    std::vector<Node> nodes(n_nodes);
    std::mutex streams_mutex;
    std::atomic<int> streams{0};

    for (int i = 0; i < n_nodes; i++) {
        auto& node = nodes[i];
        node.pk.resize(32);
        node.sk.resize(64);
        crypto_sign_keypair(
                reinterpret_cast<unsigned char*>(node.pk.data()),
                reinterpret_cast<unsigned char*>(node.sk.data()));
        node.ep = quic::Endpoint::endpoint(
                loop,
                quic::Address{"127.0.0.1", uint16_t(first_port + i)},
                quic::opt::inbound_alpn("oxenstorage"));
        node.ep->listen(
                quic::GNUTLSCreds::make_from_ed_seckey(node.sk),
                [&, i](quic::Connection& c, quic::Endpoint& e, std::optional<int64_t>) {
                    auto s = e.loop.make_shared<quic::BTRequestStream>(c, e, [](quic::message m) {
                        if (m.endpoint() != "monitor")
                            return;
                        oxenc::bt_list_consumer reqs{m.body()};
                        oxenc::bt_list_producer res;
                        while (!reqs.is_finished()) {
                            reqs.skip_value();
                            res.append_dict().append("success", 1);
                        }
                        m.respond(std::move(res).str());
                    });
                    std::lock_guard lock{streams_mutex};
                    if (!nodes[i].stream) {
                        nodes[i].stream = s;
                        streams++;
                    }
                    return s;
                });
    }

    oxenmq::OxenMQ omq;
    omq.listen_plain("tcp://127.0.0.1:" + std::to_string(oxend_port), [](auto, auto, bool) {
        return oxenmq::AuthLevel::admin;
    });
    omq.add_category("ping", oxenmq::AuthLevel::none)
            .add_request_command("ping", [](oxenmq::Message& m) { m.send_reply("pong"); });
    omq.add_category("rpc", oxenmq::AuthLevel::none)
            .add_request_command("get_service_nodes", [&](oxenmq::Message& m) {
                auto states = nlohmann::json::array();
                for (int i = 0; i < n_nodes; i++)
                    states.push_back(
                            {{"pubkey_ed25519", oxenc::to_hex(nodes[i].pk)},
                             {"public_ip", "127.0.0.1"},
                             {"storage_lmq_port", first_port + i},
                             {"swarm_id", (i % n_swarms) * (UINT64_MAX / n_swarms)}});
                m.send_reply(
                        "200",
                        nlohmann::json{
                                {"service_node_states", states},
                                {"block_hash", "aa"},
                                {"height", 1}}
                                .dump());
            });
    omq.start();

    while (streams < n_nodes)
        std::this_thread::sleep_for(50ms);

    std::atomic<size_t> max_backlog{0};
    auto sampler = loop.add_timer(20ms, [&] {
        for (auto& node : nodes) {
            auto [acked, unacked, unsent, retained] = node.stream->get_stats();
            size_t b = unacked + unsent, cur = max_backlog;
            while (b > cur && !max_backlog.compare_exchange_weak(cur, b)) {
            }
        }
    });

    // Queues the same notification on every sending node's stream.
    auto send_all = [&](std::string note) {
        loop.call([&nodes, n = senders.load(), note = std::move(note)] {
            for (int i = 0; i < n; i++)
                nodes[i].stream->command("notify", note);
        });
    };

    std::cout << "ready" << std::endl;

    std::string line;
    while (std::getline(std::cin, line)) {
        std::istringstream in{line};
        std::string cmd;
        in >> cmd;
        if (cmd == "send") {
            std::string account, hash, body;
            int ns;
            in >> account >> hash >> ns >> body;
            send_all(notification(parse_account(account), hash, ns, body_size(body, 0)));
            std::cout << "ok" << std::endl;
        } else if (cmd == "burst") {
            uint64_t first, count;
            uint32_t accounts;
            int ns;
            std::string body;
            in >> first >> count >> accounts >> ns >> body;
            for (uint64_t n = first; n < first + count; n++)
                send_all(notification(
                        indexed_account(n % accounts), message_hash(n), ns, body_size(body, n)));
            std::cout << "ok " << now_ms() << std::endl;
        } else if (cmd == "rate") {
            uint64_t per_sec, seconds, first;
            uint32_t accounts;
            int ns;
            std::string body;
            in >> per_sec >> seconds >> accounts >> ns >> body >> first;
            auto start = std::chrono::steady_clock::now();
            uint64_t total = per_sec * seconds;
            for (uint64_t k = 0; k < total; k++) {
                auto due = start + std::chrono::microseconds{k * 1'000'000 / per_sec};
                std::this_thread::sleep_until(due);
                uint64_t n = first + k;
                send_all(notification(
                        indexed_account(n % accounts), message_hash(n), ns, body_size(body, n)));
            }
            std::cout << "ok " << now_ms() << std::endl;
        } else if (cmd == "senders") {
            int n;
            in >> n;
            senders = std::clamp(n, 1, n_nodes);
            std::cout << "ok" << std::endl;
        } else if (cmd == "backlog") {
            std::cout << max_backlog.exchange(0) << std::endl;
        } else if (cmd == "quit") {
            break;
        } else {
            std::cout << "error unknown command " << cmd << std::endl;
        }
    }
    loop.remove(sampler);
    loop.call_get([&] {
        for (auto& node : nodes) {
            node.stream.reset();
            node.ep.reset();
        }
    });
    return 0;
}
