#pragma once
// GF(2^8) arithmetic for RAID6 P+Q (Reed-Solomon) parity, following the
// standard "Anvin" RAID6 construction. Primitive polynomial 0x11D, generator 2.
#include <cstdint>
#include <array>

namespace raid::gf {

struct Tables {
    std::array<std::uint8_t, 256> exp{};   // exp[i] = g^i
    std::array<std::uint8_t, 512> exp2{};  // doubled to avoid modulo in mul
    std::array<std::uint8_t, 256> log{};   // log[g^i] = i (log[0] unused)
    constexpr Tables() {
        unsigned x = 1;
        for (int i = 0; i < 255; i++) {
            exp[static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(x);
            log[x] = static_cast<std::uint8_t>(i);
            x <<= 1;
            if (x & 0x100) x ^= 0x11D;
        }
        exp[255] = exp[0];
        for (int i = 0; i < 512; i++) exp2[static_cast<std::size_t>(i)] = exp[static_cast<std::size_t>(i % 255)];
    }
};

inline const Tables& tables() {
    static const Tables t{};
    return t;
}

inline std::uint8_t mul(std::uint8_t a, std::uint8_t b) {
    if (a == 0 || b == 0) return 0;
    const auto& t = tables();
    int s = t.log[a] + t.log[b];
    return t.exp2[static_cast<std::size_t>(s)];
}

inline std::uint8_t pow2(int i) {
    // g^i, i may be negative-ish only via caller normalizing; keep i in [0,254]
    const auto& t = tables();
    return t.exp2[static_cast<std::size_t>(i % 255)];
}

inline std::uint8_t inv(std::uint8_t a) {
    // a^-1 = g^(255 - log[a]) for a != 0
    const auto& t = tables();
    if (a == 0) return 0; // undefined; callers must not invert 0
    int l = t.log[a];
    return t.exp2[static_cast<std::size_t>((255 - l) % 255)];
}

inline std::uint8_t div(std::uint8_t a, std::uint8_t b) {
    if (a == 0) return 0;
    return mul(a, inv(b));
}

} // namespace raid::gf
