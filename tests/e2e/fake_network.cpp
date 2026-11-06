// A fake oxend and a fake swarm of storage nodes for driving the hivemind end to end.
//
// usage: fake_network [--reply-delay MS] [--fail NODE:MODE:COUNT]... NODES SWARMS OXEND_PORT
//                     FIRST_QUIC_PORT
//
// oxend: oxenmq on tcp://127.0.0.1:OXEND_PORT answering ping.ping, sub.block and
// rpc.get_service_nodes with NODES nodes spread over SWARMS swarms (node i in swarm i % SWARMS),
// and sending notify.block to sub.block subscribers when the swarms change.
//
// Storage nodes: libquic on 127.0.0.1:FIRST_QUIC_PORT+i.  They answer "monitor" as today's storage
// servers do: each subscription is refused (errcode 6) unless the node's swarm stores the account,
// and otherwise kept as a monitor on the connection for 65 minutes, one per account, merging them
// all.  When a swarm change takes an account from a node, its monitors there end, with a
// monitor_ended to the connection holding them.
//
// Every notification is sent by each of the first SENDERS nodes (default: all), to the newest
// connection to it, as every member of a real swarm would; the hivemind does not check which node
// sends one.  Unlike a real node, a fake one sends it whether or not it has a monitor for the
// account, so that scenarios need not wait for subscriptions; when it has any, it sends one only if
// one of them covers the namespace, with data if any of those wants it, as a storage server does.
//
// --reply-delay MS has nodes answer monitor requests MS milliseconds after they arrive, as a
// distant node would, so that a client's requests can be seen in flight together.
//
// --fail NODE:MODE:COUNT has node NODE answer its first COUNT monitor requests by MODE: "stall"
// (no reply at all, so that the request times out), "error" (an error reply), or "entries" (every
// subscription refused as if the node knew no swarms, errcode 7).
//
// Prints "ready" once every node has had a stream from the hivemind, then reads commands on stdin,
// one per line, and answers each with one line:
//
//   send ACCOUNT HASH NS BODY_BYTES     one notification (ACCOUNT: 66 hex digits or #index)
//   burst FIRST COUNT ACCOUNTS NS BODY  COUNT notifications for messages FIRST.., spread over
//                                       accounts #0..ACCOUNTS-1; BODY is a size, or "mix"
//   rate PER_SEC SECONDS ACCOUNTS NS BODY FIRST
//                                       like burst, paced at PER_SEC for SECONDS (blocks)
//   senders N                           send from the first N nodes only
//   backlog                             largest unsent + unacked bytes on any node's stream since
//                                       the last backlog command, sampled every 20ms
//   swarms N                            move node i to swarm i % N, as a split or merge would, and
//                                       announce a new block
//   leave NODE                          oxend stops listing node NODE, which forgets its monitors
//                                       as a node that left the network would, and announces a new
//                                       block
//   join NODE                           oxend lists node NODE again, and announces a new block
//   coverage FIRST COUNT                how many listed nodes hold a live monitor of each of
//                                       accounts #FIRST..: {"by_count": {"N": A, ...},
//                                       "per_node": [L, ...]}, A being the accounts on N nodes, L
//                                       the accounts node i holds (null for one not listed)
//   lag NODE MS                         at the next swarms change, node NODE goes on refusing and
//                                       keeping monitors by its old view of the swarms for MS ms,
//                                       as a node behind oxend's does
//   check FIRST COUNT                   whether accounts #FIRST.. are subscribed on exactly the
//                                       nodes of their swarm: {"expected": E, "missing": M,
//                                       "extra": X, "monitors": T}, E being the (account, node)
//                                       pairs wanted, M those without a monitor, X the monitors of
//                                       any account on a node not of its swarm, T all monitors
//   counts                              {"requests": R, "entries": E, "wrong_swarm": W}: monitor
//                                       requests and subscriptions received, and those refused for
//                                       the wrong swarm, since the last mark
//   mark                                zeroes the counts
//   inflight                            {"now": N, "max": M}: monitor requests received and not
//                                       yet answered, now and at most since the last inflight
//   subs                                each node's swarm, monitors and counts, as JSON
//   conns                               how many nodes have a connection from the hivemind
//   drop                                closes every connection from the hivemind
//   fail NODE MODE COUNT                as --fail, from now on
//   quit
//
// Account #i is 03 || SHA256(big-endian 32-bit i), the same bytes e2e.py seeds the database with.
#include <oxenc/bt_producer.h>
#include <oxenc/bt_serialize.h>
#include <oxenc/endian.h>
#include <oxenc/hex.h>
#include <oxenmq/oxenmq.h>
#include <sodium.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <iostream>
#include <map>
#include <mutex>
#include <nlohmann/json.hpp>
#include <optional>
#include <oxen/quic/address.hpp>
#include <oxen/quic/btstream.hpp>
#include <oxen/quic/connection.hpp>
#include <oxen/quic/connection_ids.hpp>
#include <oxen/quic/endpoint.hpp>
#include <oxen/quic/gnutls_crypto.hpp>
#include <oxen/quic/loop.hpp>
#include <oxen/quic/opt.hpp>
#include <sstream>
#include <thread>
#include <unordered_map>
#include <vector>

namespace quic = oxen::quic;
using namespace std::literals;

namespace {

using steady_clock = std::chrono::steady_clock;

constexpr auto MONITOR_EXPIRY = 65min;
constexpr int64_t WRONG_SWARM = 6, NO_SWARM_INFO = 7;

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

// The storage server's placement of accounts, which the hivemind's must match.
uint64_t swarm_space(std::string_view account) {
    uint64_t res = 0;
    for (int i = 1; i < 33; i += 8)
        res ^= oxenc::load_big_to_host<uint64_t>(account.data() + i);
    return res;
}

uint64_t swarm_for(const std::vector<uint64_t>& ids, std::string_view account) {
    if (ids.size() == 1)
        return ids.front();
    auto space = swarm_space(account);
    auto right = std::lower_bound(ids.begin(), ids.end(), space);
    if (right == ids.end())
        right = ids.begin();
    auto left = std::prev(right == ids.begin() ? ids.end() : right);
    uint64_t dright = *right - space, dleft = space - *left;
    return dright < dleft ? *right : *left;
}

std::string block_hash(int64_t height) {
    char h[65];
    std::snprintf(h, sizeof h, "%064llx", (unsigned long long)height);
    return h;
}

std::string swarm_hex(uint64_t swarm) {
    char h[17];
    std::snprintf(h, sizeof h, "%llx", (unsigned long long)swarm);
    return h;
}

struct Note {
    std::string account, hash;
    int ns;
    int64_t t, z;
    size_t body;
};

// The first `len` bytes of a message's body: its hash, repeated, so that whoever receives a body
// (fake_notifier) can tell that it is the start of that message's.
std::string body_of(const Note& n, size_t len) {
    std::string b(len, '\0');
    for (size_t k = 0; k < len; ++k)
        b[k] = n.hash[k % n.hash.size()];
    return b;
}

// An account's monitor on a connection: its namespaces and data flag.
struct Monitor {
    std::vector<int16_t> ns;
    bool data = false;
    steady_clock::time_point expiry;

    bool live(steady_clock::time_point now) const { return expiry > now; }
    bool wants(int n) const { return std::binary_search(ns.begin(), ns.end(), n); }
};
// account -> its monitors on one connection
using Monitors = std::unordered_map<std::string, std::vector<Monitor>>;

size_t monitor_count(const Monitors& mons) {
    size_t n = 0;
    for (const auto& [account, ms] : mons)
        n += ms.size();
    return n;
}

bool any_live(const std::vector<Monitor>& mons, steady_clock::time_point now) {
    return std::any_of(mons.begin(), mons.end(), [&](const Monitor& m) { return m.live(now); });
}

// What one connection gets of a message in namespace `ns`: nothing unless one of the account's
// live monitors there covers it; data if any of those wants it.
struct Delivery {
    bool send = false, data = false;
};
Delivery delivery(const std::vector<Monitor>& mons, int ns, steady_clock::time_point now) {
    Delivery d;
    for (const auto& m : mons) {
        if (!m.live(now) || !m.wants(ns))
            continue;
        d.send = true;
        d.data = d.data || m.data;
    }
    return d;
}

std::string notification(const Note& n, bool data) {
    oxenc::bt_dict_producer d;
    d.append("@", n.account);
    d.append("h", n.hash);
    d.append("n", n.ns);
    d.append("t", n.t);
    d.append("z", n.z);
    if (data && n.body)
        d.append("~", body_of(n, n.body));
    return std::move(d).str();
}

struct ConnState {
    std::shared_ptr<quic::BTRequestStream> stream;
    Monitors monitors;
};

struct Node {
    std::string pk, sk;
    std::shared_ptr<quic::Endpoint> ep;
    uint64_t swarm;
    std::unordered_map<quic::ConnectionID, ConnState> conns;
    std::optional<quic::ConnectionID> current;
    bool seen = false;
    int64_t requests = 0, entries = 0, wrong_swarm = 0;
    // Whether oxend lists the node (see "leave").
    bool listed = true;
    std::string fail_mode;
    int fail_count = 0;
    // How long the node is to lag behind the next swarms change, and while it does, its view
    // before the change (its swarm, and the swarm list) and when it catches up.
    int64_t lag_ms = 0;
    std::optional<std::pair<uint64_t, std::vector<uint64_t>>> old_view;
    steady_clock::time_point behind_until{};
};

// Renews the account's monitor on a connection, or adds it: today's storage servers merge
// everything for an account on a connection into one monitor, the union of the namespaces, with
// data if any wants it.
void subscribe(std::vector<Monitor>& mons, std::vector<int16_t> ns, bool data) {
    if (mons.empty())
        mons.emplace_back();
    auto& m = mons.front();
    std::vector<int16_t> all;
    std::set_union(m.ns.begin(), m.ns.end(), ns.begin(), ns.end(), std::back_inserter(all));
    m.ns = std::move(all);
    m.data = m.data || data;
    m.expiry = steady_clock::now() + MONITOR_EXPIRY;
}

std::string ended_payload(const std::string& account, uint64_t swarm) {
    oxenc::bt_dict_producer d;
    d.append("@", account);
    d.append("errcode", WRONG_SWARM);
    d.append("error", "Account is no longer stored by this service node's swarm");
    d.append_list("snodes");
    d.append("swarm", swarm_hex(swarm));
    return std::move(d).str();
}

}  // namespace

int main(int argc, char** argv) {
    std::chrono::milliseconds reply_delay{0};
    std::vector<std::tuple<int, std::string, int>> initial_fails;
    std::vector<std::string> args;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        if (a == "--reply-delay" && i + 1 < argc)
            reply_delay = std::chrono::milliseconds{std::stoi(argv[++i])};
        else if (a == "--fail" && i + 1 < argc) {
            std::string f = argv[++i];
            auto c1 = f.find(':'), c2 = f.rfind(':');
            initial_fails.emplace_back(
                    std::stoi(f.substr(0, c1)),
                    f.substr(c1 + 1, c2 - c1 - 1),
                    std::stoi(f.substr(c2 + 1)));
        } else
            args.push_back(a);
    }
    if (args.size() != 4 || sodium_init() < 0) {
        std::cerr << "usage: fake_network [--reply-delay MS] [--fail NODE:MODE:COUNT]... "
                     "NODES SWARMS OXEND_PORT FIRST_QUIC_PORT\n";
        return 1;
    }
    int n_nodes = std::stoi(args[0]);
    uint64_t n_swarms = std::stoul(args[1]);
    int oxend_port = std::stoi(args[2]);
    int first_port = std::stoi(args[3]);
    std::atomic<int> senders{n_nodes};

    quic::Loop loop;
    // Everything below is the loop thread's, the commands reaching it through loop.call_get().
    std::vector<Node> nodes(n_nodes);
    std::vector<uint64_t> swarm_ids;
    int64_t height = 1;
    std::vector<oxenmq::ConnectionID> block_subs;
    std::atomic<int> seen{0};
    // Monitor requests received and not yet answered, now and at most since the last "inflight".
    int64_t in_flight = 0, max_in_flight = 0;

    auto assign_swarms = [&](uint64_t n) {
        std::vector<uint64_t> ids;
        for (int i = 0; i < n_nodes; i++) {
            nodes[i].swarm = (i % n) * (UINT64_MAX / n);
            ids.push_back(nodes[i].swarm);
        }
        std::sort(ids.begin(), ids.end());
        ids.erase(std::unique(ids.begin(), ids.end()), ids.end());
        swarm_ids = std::move(ids);
    };
    assign_swarms(n_swarms);

    // The node's own view of the swarms, which is oxend's but for a node still lagging behind a
    // change: its swarm, and the swarm it places `account` in.
    auto node_swarm = [&](const Node& node) {
        return node.old_view ? node.old_view->first : node.swarm;
    };
    auto node_swarm_for = [&](const Node& node, const std::string& account) {
        return swarm_for(node.old_view ? node.old_view->second : swarm_ids, account);
    };
    // Ends the node's monitors of accounts its swarm no longer stores, as a node does when it
    // learns of a swarm change.
    auto end_moved = [&](Node& node) {
        for (auto& [rid, conn] : node.conns) {
            auto& mons = conn.monitors;
            for (auto it = mons.begin(); it != mons.end();) {
                if (auto sw = node_swarm_for(node, it->first); sw != node_swarm(node)) {
                    conn.stream->command("monitor_ended", ended_payload(it->first, sw));
                    it = mons.erase(it);
                } else
                    ++it;
            }
        }
    };
    auto catch_up = [&] {
        auto now = steady_clock::now();
        for (auto& node : nodes)
            if (node.old_view && now >= node.behind_until) {
                node.old_view.reset();
                end_moved(node);
            }
    };
    for (auto& [node, mode, count] : initial_fails) {
        nodes.at(node).fail_mode = mode;
        nodes.at(node).fail_count = count;
    }

    auto on_monitor = [&](Node& node, ConnState& conn, quic::message& m) {
        catch_up();
        node.requests++;
        max_in_flight = std::max(max_in_flight, ++in_flight);
        std::string fail;
        if (node.fail_count > 0) {
            node.fail_count--;
            fail = node.fail_mode;
        }
        // A stalled request counts as in flight for good, as it would for its sender until it times
        // out.
        if (fail == "stall")
            return;
        auto respond = [&](std::string body, bool error = false) {
            if (reply_delay == 0ms) {
                in_flight--;
                return m.respond(body, error);
            }
            loop.call_later(reply_delay, [&, m, body = std::move(body), error] {
                in_flight--;
                m.respond(body, error);
            });
        };
        if (fail == "error")
            return respond("Internal error", true);
        auto& mons = conn.monitors;
        oxenc::bt_list_consumer reqs{m.body()};
        oxenc::bt_list_producer res;
        while (!reqs.is_finished()) {
            node.entries++;
            auto d = reqs.consume_dict_consumer();
            auto ed = d.maybe<std::string_view>("P");
            bool data = d.maybe<int>("d").value_or(0) != 0;
            std::vector<int16_t> ns;
            for (auto l = d.require<oxenc::bt_list_consumer>("n"); !l.is_finished();)
                ns.push_back(l.consume_integer<int16_t>());
            std::sort(ns.begin(), ns.end());
            std::string account;
            bool bad_key = false;
            if (ed) {
                account.resize(33);
                account[0] = 0x05;
                bad_key = ed->size() != 32 ||
                          crypto_sign_ed25519_pk_to_curve25519(
                                  reinterpret_cast<unsigned char*>(account.data() + 1),
                                  reinterpret_cast<const unsigned char*>(ed->data())) != 0;
            } else
                account = d.require<std::string>("p");

            auto r = res.append_dict();
            if (bad_key) {
                r.append("errcode", 1);
                r.append("error", "Invalid pubkey");
                continue;
            }
            if (fail == "entries") {
                r.append("errcode", NO_SWARM_INFO);
                r.append("error", "Service node does not currently know the swarm list");
                continue;
            }
            if (auto sw = node_swarm_for(node, account); sw != node_swarm(node)) {
                node.wrong_swarm++;
                r.append("errcode", WRONG_SWARM);
                r.append("error", "Account is not stored by this service node's swarm");
                r.append_list("snodes");
                r.append("swarm", swarm_hex(sw));
                continue;
            }
            subscribe(mons[account], std::move(ns), data);
            r.append("success", 1);
        }
        respond(std::move(res).str());
    };

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
                    auto& node = nodes[i];
                    auto rid = c.reference_id();
                    auto s = e.loop.make_shared<quic::BTRequestStream>(
                            c, e, [&, i, rid](quic::message m) {
                                auto& node = nodes[i];
                                auto it = node.conns.find(rid);
                                if (it == node.conns.end())
                                    return;
                                if (m.endpoint() == "monitor")
                                    on_monitor(node, it->second, m);
                                else
                                    // As a storage server does any command it does not know.
                                    throw quic::no_such_endpoint{};
                            });
                    auto& conn = node.conns[rid];
                    if (!conn.stream) {
                        conn.stream = s;
                        node.current = rid;
                        if (!node.seen) {
                            node.seen = true;
                            seen++;
                        }
                    }
                    return s;
                },
                quic::connection_closed_callback{[&, i](quic::Connection& c, uint64_t) {
                    auto& node = nodes[i];
                    auto rid = c.reference_id();
                    auto it = node.conns.find(rid);
                    if (it == node.conns.end())
                        return;
                    node.conns.erase(it);
                    if (node.current == rid)
                        node.current = node.conns.empty()
                                             ? std::nullopt
                                             : std::make_optional(node.conns.begin()->first);
                }});
    }

    oxenmq::OxenMQ omq;
    omq.listen_plain("tcp://127.0.0.1:" + std::to_string(oxend_port), [](auto, auto, bool) {
        return oxenmq::AuthLevel::admin;
    });
    omq.add_category("ping", oxenmq::AuthLevel::none)
            .add_request_command("ping", [](oxenmq::Message& m) { m.send_reply("pong"); });
    omq.add_category("sub", oxenmq::AuthLevel::none)
            .add_request_command("block", [&](oxenmq::Message& m) {
                loop.call_get([&] {
                    if (std::find(block_subs.begin(), block_subs.end(), m.conn) == block_subs.end())
                        block_subs.push_back(m.conn);
                });
                m.send_reply("OK");
            });
    omq.add_category("rpc", oxenmq::AuthLevel::none)
            .add_request_command("get_service_nodes", [&](oxenmq::Message& m) {
                auto reply = loop.call_get([&] {
                    auto states = nlohmann::json::array();
                    for (int i = 0; i < n_nodes; i++) {
                        if (!nodes[i].listed)
                            continue;
                        states.push_back(
                                {{"pubkey_ed25519", oxenc::to_hex(nodes[i].pk)},
                                 {"public_ip", "127.0.0.1"},
                                 {"storage_lmq_port", first_port + i},
                                 {"swarm_id", nodes[i].swarm}});
                    }
                    return nlohmann::json{
                            {"service_node_states", states},
                            {"block_hash", block_hash(height)},
                            {"height", height}}
                            .dump();
                });
                m.send_reply("200", reply);
            });
    omq.start();

    while (seen < n_nodes)
        std::this_thread::sleep_for(50ms);

    std::atomic<size_t> max_backlog{0};
    auto sampler = loop.add_timer(20ms, [&] {
        for (auto& node : nodes) {
            if (!node.current)
                continue;
            auto [acked, unacked, unsent, retained] =
                    node.conns.at(*node.current).stream->get_stats();
            size_t b = unacked + unsent, cur = max_backlog;
            while (b > cur && !max_backlog.compare_exchange_weak(cur, b)) {
            }
        }
    });

    // A sending node sends to its newest connection.
    auto deliver = [&](Node& node, const Note& note) {
        auto now = steady_clock::now();
        if (!node.current)
            return;
        auto& conn = node.conns.at(*node.current);
        auto& mons = conn.monitors;
        if (auto it = mons.find(note.account); it != mons.end()) {
            if (auto d = delivery(it->second, note.ns, now); d.send)
                conn.stream->command("notify", notification(note, d.data));
        } else
            conn.stream->command("notify", notification(note, true));
    };

    // Sends the same notification from every sending node.
    auto send_all = [&](Note note) {
        loop.call([&, n = senders.load(), note = std::move(note)] {
            for (int i = 0; i < n; i++)
                deliver(nodes[i], note);
        });
    };
    auto make_note = [](std::string account, std::string hash, int ns, size_t body) {
        auto t = now_ms();
        return Note{std::move(account), std::move(hash), ns, t, t + 14 * 86400 * 1000LL, body};
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
            send_all(make_note(parse_account(account), hash, ns, body_size(body, 0)));
            std::cout << "ok" << std::endl;
        } else if (cmd == "burst") {
            uint64_t first, count;
            uint32_t accounts;
            int ns;
            std::string body;
            in >> first >> count >> accounts >> ns >> body;
            for (uint64_t n = first; n < first + count; n++)
                send_all(make_note(
                        indexed_account(n % accounts), message_hash(n), ns, body_size(body, n)));
            std::cout << "ok " << now_ms() << std::endl;
        } else if (cmd == "rate") {
            uint64_t per_sec, seconds, first;
            uint32_t accounts;
            int ns;
            std::string body;
            in >> per_sec >> seconds >> accounts >> ns >> body >> first;
            auto start = steady_clock::now();
            uint64_t total = per_sec * seconds;
            for (uint64_t k = 0; k < total; k++) {
                auto due = start + std::chrono::microseconds{k * 1'000'000 / per_sec};
                std::this_thread::sleep_until(due);
                uint64_t n = first + k;
                send_all(make_note(
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
        } else if (cmd == "swarms") {
            uint64_t n;
            in >> n;
            loop.call_get([&] {
                catch_up();
                auto now = steady_clock::now();
                for (auto& node : nodes)
                    if (node.lag_ms > 0) {
                        node.old_view.emplace(node.swarm, swarm_ids);
                        node.behind_until = now + std::chrono::milliseconds{node.lag_ms};
                        node.lag_ms = 0;
                    }
                assign_swarms(std::max<uint64_t>(n, 1));
                for (auto& node : nodes)
                    if (!node.old_view)
                        end_moved(node);
                height++;
                for (auto& c : block_subs)
                    omq.send(c, "notify.block", std::to_string(height), block_hash(height));
            });
            std::cout << "ok" << std::endl;
        } else if (cmd == "leave" || cmd == "join") {
            int i;
            in >> i;
            loop.call_get([&] {
                auto& node = nodes.at(i);
                node.listed = cmd == "join";
                if (!node.listed)
                    for (auto& [rid, conn] : node.conns)
                        conn.monitors.clear();
                height++;
                for (auto& c : block_subs)
                    omq.send(c, "notify.block", std::to_string(height), block_hash(height));
            });
            std::cout << "ok" << std::endl;
        } else if (cmd == "coverage") {
            uint32_t first, count;
            in >> first >> count;
            std::cout << loop.call_get([&] {
                auto now = steady_clock::now();
                auto holds = [&](Node& node, const std::string& account) {
                    for (auto& [rid, conn] : node.conns)
                        if (auto it = conn.monitors.find(account);
                            it != conn.monitors.end() && any_live(it->second, now))
                            return true;
                    return false;
                };
                std::map<int, int64_t> by_count;
                std::vector<int64_t> per_node(nodes.size(), 0);
                for (uint32_t a = first; a < first + count; a++) {
                    auto account = indexed_account(a);
                    int n = 0;
                    for (size_t i = 0; i < nodes.size(); i++)
                        if (nodes[i].listed && holds(nodes[i], account)) {
                            n++;
                            per_node[i]++;
                        }
                    by_count[n]++;
                }
                nlohmann::json j{
                        {"by_count", nlohmann::json::object()},
                        {"per_node", nlohmann::json::array()}};
                for (auto& [n, accounts] : by_count)
                    j["by_count"][std::to_string(n)] = accounts;
                for (size_t i = 0; i < nodes.size(); i++)
                    j["per_node"].push_back(
                            nodes[i].listed ? nlohmann::json(per_node[i]) : nlohmann::json());
                return j.dump();
            }) << std::endl;
        } else if (cmd == "lag") {
            int i;
            int64_t ms;
            in >> i >> ms;
            loop.call_get([&] { nodes.at(i).lag_ms = ms; });
            std::cout << "ok" << std::endl;
        } else if (cmd == "check") {
            uint32_t first, count;
            in >> first >> count;
            std::cout << loop.call_get([&] {
                catch_up();
                auto now = steady_clock::now();
                auto live_on = [&](Node& node, const std::string& account) {
                    for (auto& [rid, conn] : node.conns)
                        if (auto it = conn.monitors.find(account);
                            it != conn.monitors.end() && any_live(it->second, now))
                            return true;
                    return false;
                };
                int64_t expected = 0, missing = 0, extra = 0, monitors = 0;
                for (uint32_t i = first; i < first + count; i++) {
                    auto account = indexed_account(i);
                    auto sw = swarm_for(swarm_ids, account);
                    for (auto& node : nodes)
                        if (node.swarm == sw) {
                            expected++;
                            missing += !live_on(node, account);
                        }
                }
                auto count_mons = [&](Node& node, const Monitors& mons) {
                    for (auto& [account, ms] : mons)
                        for (auto& mon : ms)
                            if (mon.live(now)) {
                                monitors++;
                                extra += swarm_for(swarm_ids, account) != node.swarm;
                            }
                };
                for (auto& node : nodes)
                    for (auto& [rid, conn] : node.conns)
                        count_mons(node, conn.monitors);
                return nlohmann::json{
                        {"expected", expected},
                        {"missing", missing},
                        {"extra", extra},
                        {"monitors", monitors}}
                        .dump();
            }) << std::endl;
        } else if (cmd == "counts" || cmd == "subs") {
            std::cout << loop.call_get([&] {
                auto all = nlohmann::json::array();
                nlohmann::json total{{"requests", 0}, {"entries", 0}, {"wrong_swarm", 0}};
                for (auto& node : nodes) {
                    int64_t monitors = 0;
                    for (auto& [rid, conn] : node.conns)
                        monitors += monitor_count(conn.monitors);
                    nlohmann::json n{
                            {"swarm", swarm_hex(node.swarm)},
                            {"monitors", monitors},
                            {"requests", node.requests},
                            {"entries", node.entries},
                            {"wrong_swarm", node.wrong_swarm}};
                    for (auto& [k, v] : total.items())
                        v = v.get<int64_t>() + n[k].get<int64_t>();
                    all.push_back(std::move(n));
                }
                return (cmd == "subs" ? all : total).dump();
            }) << std::endl;
        } else if (cmd == "inflight") {
            std::cout << loop.call_get([&] {
                auto r = nlohmann::json{{"now", in_flight}, {"max", max_in_flight}}.dump();
                max_in_flight = in_flight;
                return r;
            }) << std::endl;
        } else if (cmd == "mark") {
            loop.call_get([&] {
                for (auto& node : nodes)
                    node.requests = node.entries = node.wrong_swarm = 0;
            });
            std::cout << "ok" << std::endl;
        } else if (cmd == "conns") {
            std::cout << loop.call_get([&] {
                return std::count_if(nodes.begin(), nodes.end(), [](const Node& n) {
                    return n.current.has_value();
                });
            }) << std::endl;
        } else if (cmd == "drop") {
            loop.call_get([&] {
                for (auto& node : nodes) {
                    std::vector<quic::ConnectionID> rids;
                    for (auto& [rid, conn] : node.conns)
                        rids.push_back(rid);
                    for (auto& rid : rids)
                        if (auto c = node.ep->get_conn(rid))
                            c->close_connection();
                }
            });
            std::cout << "ok" << std::endl;
        } else if (cmd == "fail") {
            int node, count;
            std::string mode;
            in >> node >> mode >> count;
            loop.call_get([&] {
                nodes.at(node).fail_mode = mode;
                nodes.at(node).fail_count = count;
            });
            std::cout << "ok" << std::endl;
        } else if (cmd == "quit") {
            break;
        } else {
            std::cout << "error unknown command " << cmd << std::endl;
        }
    }
    loop.remove(sampler);
    loop.call_get([&] {
        for (auto& node : nodes) {
            node.conns.clear();
            node.ep.reset();
        }
    });
    return 0;
}
