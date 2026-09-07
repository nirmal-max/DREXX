#include "raid/layout.hpp"
#include <algorithm>

// RAID10 reconstruction.
//
// Layout supported: "near" 2-copy mirroring with adjacent member pairing —
// members (0,1) are a mirror pair, (2,3) are the next mirror pair, and so
// on. Data is striped round-robin across the mirror pairs the same way
// RAID0 stripes across disks. This matches Linux mdraid's default n2
// layout for the common case of adjacent device ordering. DREX does NOT
// claim support for mdraid's "far" (f2) or "offset" (o2) layouts, or for
// mirror counts other than 2 — those are out of scope for this
// implementation and are refused (see read_raid10 below) rather than
// silently mis-decoded.
//
// Requires an even member count (every mirror pair has exactly 2 copies).
// A stripe row is only readable if at least one member of its mirror pair
// is present; if both copies of a pair are missing, that data is
// unrecoverable and the read is refused.

namespace raid {

int raid10_module_anchor() { return 10; }

bool read_raid10(const Layout& l, const std::vector<std::unique_ptr<ISource>>& s,
                  std::uint64_t o, std::span<std::byte> b) {
    auto n = s.size();
    if (n < 2 || n % 2 != 0) return false; // only 2-copy adjacent-pair layout supported
    std::size_t groups = n / 2;
    auto chunk = static_cast<std::uint64_t>(l.stripe_sectors) * 512;
    if (chunk == 0) return false;
    std::size_t done = 0;
    while (done < b.size()) {
        auto lo = o + done;
        auto stripe = lo / chunk;
        auto g = static_cast<std::size_t>(stripe % groups);
        auto row = stripe / groups;
        auto intra = lo % chunk;
        auto take = std::min<std::uint64_t>(chunk - intra, b.size() - done);
        auto member_off = row * chunk + intra;
        std::size_t take_sz = static_cast<std::size_t>(take);

        auto& a = s[2 * g];
        auto& c = s[2 * g + 1];
        bool ok = false;
        if (a) ok = a->read_at(member_off, b.subspan(done, take_sz));
        if (!ok && c) ok = c->read_at(member_off, b.subspan(done, take_sz));
        if (!ok) return false; // both mirror copies missing/unreadable: unrecoverable

        done += take_sz;
    }
    return true;
}

} // namespace raid
