#include "raid/layout.hpp"
#include "raid/galois.hpp"
#include <algorithm>
#include <vector>

// RAID6 (P+Q) reconstruction.
//
// Layout supported: dedicated (non-rotating) parity members. The LAST TWO
// entries of the member/source list are treated as the P and Q parity
// members respectively; the first (n-2) members are data members, striped
// round-robin the same way RAID0 is. This is a real, standards-based RAID6
// layout (matching e.g. some hardware RAID controllers' "RAID6 dedicated
// parity" mode), but it is NOT the rotating-parity layout Linux mdraid uses
// by default. DREX does not currently detect/claim mdraid's rotating RAID6
// layout; only this dedicated-parity layout is implemented and wired in.
//
// P = XOR of all data blocks in a stripe row.
// Q = sum_i (g^i * D_i) in GF(2^8), g=2, i = data-member index (0-based).
//
// Recoverable: 0, 1, or 2 missing members among a stripe row's (data+P+Q)
// set, provided enough independent equations remain (see recover_row).
// 3+ missing, or 2 missing data members while a parity is also missing,
// is refused (function returns false) rather than fabricating data.

namespace raid {

int raid6_module_anchor() { return 6; }

namespace {

using gf::mul;
using gf::pow2;

bool recover_row(std::size_t k, std::size_t take,
                  const std::vector<bool>& data_present,
                  const std::vector<std::vector<std::byte>>& data_bytes,
                  bool p_present, const std::vector<std::byte>& p_bytes,
                  bool q_present, const std::vector<std::byte>& q_bytes,
                  std::vector<std::vector<std::byte>>& out) {
    std::vector<std::size_t> missing_data;
    for (std::size_t i = 0; i < k; i++)
        if (!data_present[i]) missing_data.push_back(i);

    if (missing_data.empty()) {
        out = data_bytes;
        return true;
    }

    if (missing_data.size() == 1) {
        std::size_t td = missing_data[0];
        out = data_bytes;
        if (p_present) {
            std::vector<std::byte> acc = p_bytes;
            for (std::size_t i = 0; i < k; i++) {
                if (i == td) continue;
                for (std::size_t b = 0; b < take; b++)
                    acc[b] = std::byte(static_cast<unsigned char>(
                        std::to_integer<unsigned char>(acc[b]) ^
                        std::to_integer<unsigned char>(data_bytes[i][b])));
            }
            out[td] = acc;
            return true;
        }
        if (q_present) {
            std::vector<std::byte> acc = q_bytes;
            for (std::size_t i = 0; i < k; i++) {
                if (i == td) continue;
                std::uint8_t coef = pow2(static_cast<int>(i));
                for (std::size_t b = 0; b < take; b++) {
                    auto term = mul(coef, std::to_integer<unsigned char>(data_bytes[i][b]));
                    acc[b] = std::byte(static_cast<unsigned char>(std::to_integer<unsigned char>(acc[b]) ^ term));
                }
            }
            std::uint8_t inv_coef = gf::inv(pow2(static_cast<int>(td)));
            for (std::size_t b = 0; b < take; b++)
                acc[b] = std::byte(mul(inv_coef, std::to_integer<unsigned char>(acc[b])));
            out[td] = acc;
            return true;
        }
        return false;
    }

    if (missing_data.size() == 2) {
        if (!p_present || !q_present) return false;
        std::size_t t1 = missing_data[0], t2 = missing_data[1];
        out = data_bytes;
        std::vector<std::byte> A = p_bytes;
        std::vector<std::byte> Aq(take, std::byte{});
        for (std::size_t i = 0; i < k; i++) {
            if (i == t1 || i == t2) continue;
            std::uint8_t coef = pow2(static_cast<int>(i));
            for (std::size_t b = 0; b < take; b++) {
                A[b] = std::byte(static_cast<unsigned char>(
                    std::to_integer<unsigned char>(A[b]) ^ std::to_integer<unsigned char>(data_bytes[i][b])));
                auto term = mul(coef, std::to_integer<unsigned char>(data_bytes[i][b]));
                Aq[b] = std::byte(static_cast<unsigned char>(std::to_integer<unsigned char>(Aq[b]) ^ term));
            }
        }
        std::uint8_t g1 = pow2(static_cast<int>(t1));
        std::uint8_t g2 = pow2(static_cast<int>(t2));
        std::uint8_t denom = static_cast<std::uint8_t>(g1 ^ g2);
        std::vector<std::byte> d1(take), d2(take);
        for (std::size_t b = 0; b < take; b++) {
            unsigned char rhs2 = static_cast<unsigned char>(std::to_integer<unsigned char>(q_bytes[b]) ^ std::to_integer<unsigned char>(Aq[b]));
            unsigned char g2_A = mul(g2, std::to_integer<unsigned char>(A[b]));
            unsigned char numer = static_cast<unsigned char>(rhs2 ^ g2_A);
            unsigned char dt1 = gf::div(numer, denom);
            unsigned char dt2 = static_cast<unsigned char>(std::to_integer<unsigned char>(A[b]) ^ dt1);
            d1[b] = std::byte(dt1);
            d2[b] = std::byte(dt2);
        }
        out[t1] = d1;
        out[t2] = d2;
        return true;
    }

    return false;
}

} // namespace

bool read_raid6(const Layout& l, const std::vector<std::unique_ptr<ISource>>& s,
                 std::uint64_t o, std::span<std::byte> b) {
    auto n = s.size();
    if (n < 3) return false;
    std::size_t k = n - 2;
    std::size_t p_idx = n - 2, q_idx = n - 1;
    auto chunk = static_cast<std::uint64_t>(l.stripe_sectors) * 512;
    if (chunk == 0) return false;
    std::size_t done = 0;
    while (done < b.size()) {
        auto lo = o + done;
        auto stripe = lo / chunk;
        auto td = static_cast<std::size_t>(stripe % k);
        auto data_row = stripe / k;
        auto intra = lo % chunk;
        auto take = std::min<std::uint64_t>(chunk - intra, b.size() - done);
        auto member_off = data_row * chunk + intra;
        std::size_t take_sz = static_cast<std::size_t>(take);

        if (s[td]) {
            if (!s[td]->read_at(member_off, b.subspan(done, take_sz))) return false;
            done += take_sz;
            continue;
        }

        std::vector<bool> present(k, false);
        std::vector<std::vector<std::byte>> data_bytes(k, std::vector<std::byte>(take_sz));
        for (std::size_t i = 0; i < k; i++) {
            if (s[i]) {
                if (!s[i]->read_at(member_off, std::span<std::byte>(data_bytes[i]))) return false;
                present[i] = true;
            }
        }
        bool p_present = static_cast<bool>(s[p_idx]);
        bool q_present = static_cast<bool>(s[q_idx]);
        std::vector<std::byte> p_bytes(take_sz), q_bytes(take_sz);
        if (p_present && !s[p_idx]->read_at(member_off, std::span<std::byte>(p_bytes))) return false;
        if (q_present && !s[q_idx]->read_at(member_off, std::span<std::byte>(q_bytes))) return false;

        std::vector<std::vector<std::byte>> recovered(k);
        if (!recover_row(k, take_sz, present, data_bytes, p_present, p_bytes, q_present, q_bytes, recovered))
            return false;

        std::copy(recovered[td].begin(), recovered[td].end(), b.begin() + static_cast<long>(done));
        done += take_sz;
    }
    return true;
}

} // namespace raid
