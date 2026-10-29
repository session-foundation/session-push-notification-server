#pragma once

#include <oxenc/common.h>
#include <sodium/crypto_generichash_blake2b.h>

#include <cassert>
#include <charconv>
#include <ranges>
#include <span>
#include <string>
#include <string_view>

#include "bytes.hpp"
#include "utils.hpp"

namespace spns {

template <typename T>
concept byte_spannable =
        std::ranges::contiguous_range<T> && oxenc::basic_char<std::ranges::range_value_t<T>>;

namespace detail {
    template <std::integral T>
        requires(sizeof(T) <= 8)
    void blake2b_update(crypto_generichash_blake2b_state& s, const T& val) {
        char buf[20];
        auto [end, ec] = std::to_chars(std::begin(buf), std::end(buf), val);
        assert(ec == std::errc());
        crypto_generichash_blake2b_update(
                &s, reinterpret_cast<const unsigned char*>(buf), end - buf);
    }

    template <byte_spannable T>
    void blake2b_update(crypto_generichash_blake2b_state& s, const T& val) {
        crypto_generichash_blake2b_update(
                &s,
                reinterpret_cast<const unsigned char*>(std::ranges::data(val)),
                std::ranges::size(val));
    }
}  // namespace detail

template <bytes_derived Hash, byte_spannable K, typename... T>
void blake2b_keyed(Hash& result, const K& key, const T&... args) {
    crypto_generichash_blake2b_state s;
    crypto_generichash_blake2b_init(
            &s,
            reinterpret_cast<const unsigned char*>(std::ranges::data(key)),
            std::ranges::size(key),
            result.SIZE);
    (detail::blake2b_update(s, args), ...);
    crypto_generichash_blake2b_final(&s, result, result.SIZE);
}

template <bytes_derived Hash = Blake2B_32, byte_spannable K, typename... T>
Hash blake2b_keyed(const K& key, const T&... args) {
    Hash result;
    blake2b_keyed(result, key, args...);
    return result;
}

template <typename Hash = Blake2B_32, typename... T>
Hash blake2b(const T&... args) {
    return blake2b_keyed<Hash>(""sv, args...);
}

}  // namespace spns
