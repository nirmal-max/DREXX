#include "quick/partition.hpp"
#include <array>
#include <cstring>

namespace quick {
static std::uint16_t u16(const std::byte* p) {
    return std::uint16_t(std::to_integer<unsigned char>(p[0])) |
           (std::uint16_t(std::to_integer<unsigned char>(p[1])) << 8);
}
static std::uint32_t u32(const std::byte* p) {
    return std::uint32_t(std::to_integer<unsigned char>(p[0])) |
           (std::uint32_t(std::to_integer<unsigned char>(p[1])) << 8) |
           (std::uint32_t(std::to_integer<unsigned char>(p[2])) << 16) |
           (std::uint32_t(std::to_integer<unsigned char>(p[3])) << 24);
}
static std::uint64_t u64(const std::byte* p) {
    std::uint64_t x=0; for(int i=0;i<8;i++) x |= std::uint64_t(std::to_integer<unsigned char>(p[i])) << (8*i); return x;
}
static std::string guid_string(const std::byte* p) {
    static const char* h="0123456789abcdef";
    auto bytehex=[&](int i){std::string x; x+=h[(std::to_integer<unsigned char>(p[i])>>4)&15]; x+=h[std::to_integer<unsigned char>(p[i])&15]; return x;};
    std::string s;
    // GPT GUID fields 0..7 are displayed with the first three fields little-endian.
    for(int i=3;i>=0;--i) s+=bytehex(i);
    s+='-';
    for(int i=5;i>=4;--i) s+=bytehex(i);
    s+='-';
    for(int i=7;i>=6;--i) s+=bytehex(i);
    s+='-';
    for(int i=8;i<10;++i) s+=bytehex(i);
    s+='-';
    for(int i=10;i<16;++i) s+=bytehex(i);
    return s;
}
std::vector<Partition> analyze_partitions(ISource& src, std::vector<std::string>& warnings) {
    std::vector<Partition> out;
    std::array<std::byte,512> b{};
    if (!src.read_at(0, b)) { warnings.push_back("partition table unreadable"); return out; }
    if (u16(b.data()+510)==0xAA55) {
        bool protective=false;
        for(int i=0;i<4;i++) {
            auto e=b.data()+446+i*16;
            unsigned type=std::to_integer<unsigned char>(e[4]);
            if(type==0xEE) protective=true;
            if(type!=0) {
                Partition p{};
                p.index=static_cast<std::uint32_t>(i+1);
                p.offset=u32(e+8)*512ULL;
                p.size=u32(e+12)*512ULL;
                p.type="MBR:0x"+std::to_string(type);
                if(p.offset < src.size() && p.size <= src.size()-p.offset) out.push_back(p);
            }
        }
        if(protective) {
            std::array<std::byte,512> g{};
            if(src.read_at(512,g) && std::memcmp(g.data(),"EFI PART",8)==0) {
                std::uint64_t entries_lba=u64(g.data()+72), count=u32(g.data()+80), entry_size=u32(g.data()+84);
                if(entry_size>=128 && entry_size<=4096 && count<=4096) {
                    std::vector<std::byte> e(entry_size);
                    out.clear();
                    for(std::uint32_t i=0;i<count;i++) {
                        auto off=entries_lba*512ULL+std::uint64_t(i)*entry_size;
                        if(off > src.size() || entry_size > src.size()-off) break;
                        if(!src.read_at(off,e)) break;
                        bool zero=true; for(int j=0;j<16;j++) if(e[j]!=std::byte{0}) {zero=false;break;}
                        if(zero) continue;
                        std::uint64_t first=u64(e.data()+32), last=u64(e.data()+40);
                        if(last<first) continue;
                        Partition p{};
                        p.index=i+1; p.offset=first*512ULL; p.size=(last-first+1)*512ULL;
                        p.type="GPT:"+guid_string(e.data());
                        if(p.offset<src.size() && p.size<=src.size()-p.offset) out.push_back(p);
                    }
                }
            }
        }
    }
    if(out.empty()) {
        Partition p{}; p.index=0; p.offset=0; p.size=src.size(); p.type="WHOLE_SOURCE"; out.push_back(p);
    }
    return out;
}
}
