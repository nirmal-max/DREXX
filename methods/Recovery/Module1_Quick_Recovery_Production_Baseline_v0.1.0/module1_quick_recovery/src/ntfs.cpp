#include "quick/ntfs.hpp"
#include <array>
#include <cstring>
#include <fstream>
#include <algorithm>
#include <limits>

namespace quick {
static std::uint16_t le16(const std::byte*p){return std::uint16_t(std::to_integer<unsigned char>(p[0]))|(std::uint16_t(std::to_integer<unsigned char>(p[1]))<<8);}
static std::uint32_t le32(const std::byte*p){return std::uint32_t(std::to_integer<unsigned char>(p[0]))|(std::uint32_t(std::to_integer<unsigned char>(p[1]))<<8)|(std::uint32_t(std::to_integer<unsigned char>(p[2]))<<16)|(std::uint32_t(std::to_integer<unsigned char>(p[3]))<<24);}
static std::uint64_t le64(const std::byte*p){std::uint64_t x=0;for(int i=0;i<8;i++)x|=std::uint64_t(std::to_integer<unsigned char>(p[i]))<<(8*i);return x;}
static std::int64_t sle64(const std::byte*p){return static_cast<std::int64_t>(le64(p));}
static bool u16ok(std::uint64_t x){return x<=65535;}
static std::string utf16le(const std::byte*p,size_t chars){
    std::string s; s.reserve(chars);
    for(size_t i=0;i<chars;i++){auto u=le16(p+2*i); if(u<0x80)s.push_back(char(u)); else if(u<0x800){s.push_back(char(0xC0|(u>>6)));s.push_back(char(0x80|(u&63)));} else {s.push_back(char(0xE0|(u>>12)));s.push_back(char(0x80|((u>>6)&63)));s.push_back(char(0x80|(u&63)));}}
    return s;
}
struct Run { std::uint64_t vcn; std::uint64_t lcn; std::uint64_t len; };
static bool parse_runs(const std::byte* p,size_t n,std::vector<Run>& runs){
    size_t i=0; std::uint64_t vcn=0,lcn=0;
    while(i<n){
        unsigned h=std::to_integer<unsigned char>(p[i++]); if(!h) break;
        unsigned ls=h&0x0F, os=h>>4; if(!ls || ls>8 || os>8 || i+ls+os>n) return false;
        std::uint64_t len=0; for(unsigned j=0;j<ls;j++) len|=std::uint64_t(std::to_integer<unsigned char>(p[i+j]))<<(8*j);
        std::int64_t delta=0;
        if(os){ std::uint64_t raw=0; for(unsigned j=0;j<os;j++) raw|=std::uint64_t(std::to_integer<unsigned char>(p[i+ls+j]))<<(8*j); if(std::to_integer<unsigned char>(p[i+ls+os-1])&0x80) raw|=(~0ULL)<<(8*os); delta=static_cast<std::int64_t>(raw); }
        i+=ls+os; if(delta<0 && static_cast<std::uint64_t>(-delta)>lcn) return false;
        lcn=static_cast<std::uint64_t>(static_cast<std::int64_t>(lcn)+delta);
        runs.push_back({vcn,lcn,len}); vcn+=len;
    }
    return !runs.empty();
}
static bool apply_usa(std::vector<std::byte>& rec, std::uint32_t sector){
    if(rec.size()<8) return false; auto usa_off=le16(rec.data()+4), usa_count=le16(rec.data()+6);
    if(!usa_off || !usa_count || usa_off+2ULL*usa_count>rec.size()) return false;
    auto seq=le16(rec.data()+usa_off);
    for(std::uint32_t i=1;i<usa_count;i++){size_t pos=size_t(i)*sector-2;if(pos+2>rec.size())return false;if(le16(rec.data()+pos)!=seq)return false;std::memcpy(rec.data()+pos,rec.data()+usa_off+2*i,2);}
    return true;
}
static bool read_clusters(ISource& src,std::uint64_t base,std::uint64_t cluster_size,const std::vector<Run>&runs,std::uint64_t wanted,std::vector<std::byte>&out){
    out.clear(); out.resize(static_cast<size_t>(wanted)); std::uint64_t copied=0;
    for(auto&r:runs){ if(copied>=wanted)break; auto bytes=std::min<std::uint64_t>(r.len*cluster_size,wanted-copied); if(r.lcn==0) {std::memset(out.data()+copied,0,static_cast<size_t>(bytes));} else {if(!src.read_at(base+r.lcn*cluster_size,std::span<std::byte>(out.data()+copied,static_cast<size_t>(bytes)))) return false;} copied+=bytes; }
    return copied==wanted;
}
bool NtfsProvider::scan(ISource& src, const FsContext& fs, std::vector<Candidate>& out,
                          std::vector<std::string>& warnings, std::function<bool()> cancelled) {
    std::array<std::byte, 512> b{};
    if (!src.read_at(fs.offset, b)) { warnings.push_back("NTFS boot sector unreadable"); return false; }
    auto bps = le16(b.data()+11);
    auto spc = std::to_integer<unsigned char>(b[13]);
    if (!bps || !spc) { warnings.push_back("invalid NTFS geometry"); return false; }
    auto cluster = std::uint64_t(bps) * spc;
    auto mft_lcn = le64(b.data()+48);
    auto rec_raw = static_cast<std::int8_t>(std::to_integer<unsigned char>(b[64]));
    std::uint64_t rec_size = rec_raw < 0 ? (1ULL << (-rec_raw)) : std::uint64_t(rec_raw) * cluster;
    if (rec_size < 512 || rec_size > 1024*1024) { warnings.push_back("unsupported NTFS record size"); return false; }
    auto mft_off = fs.offset + mft_lcn * cluster;
    std::uint64_t max_records = fs.size / rec_size;
    max_records = std::min<std::uint64_t>(max_records, 4'000'000);

    for (std::uint64_t id=0; id<max_records; ++id) {
        if (cancelled && cancelled()) return false;
        std::vector<std::byte> rec(static_cast<size_t>(rec_size));
        if (!src.read_at(mft_off + id*rec_size, rec)) break;
        if (std::memcmp(rec.data(), "FILE", 4) != 0) continue;
        if (!apply_usa(rec, bps)) continue;
        auto flags = le16(rec.data()+22);
        if (flags & 1) continue; // active record, not a deleted candidate
        auto attr_off = le16(rec.data()+20);
        if (attr_off >= rec.size()) continue;

        std::string name;
        std::vector<Extent> exts;
        std::uint64_t size = 0;
        bool data_found = false;
        size_t pos = attr_off;
        while (pos + 16 <= rec.size()) {
            auto type = le32(rec.data()+pos);
            if (type == 0xFFFFFFFF) break;
            auto len = le32(rec.data()+pos+4);
            if (len < 24 || pos + len > rec.size()) break;
            auto nonres = std::to_integer<unsigned char>(rec[pos+8]);

            if (type == 0x30 && !nonres) {
                auto vl = le32(rec.data()+pos+16);
                auto vo = le16(rec.data()+pos+20);
                if (vo + vl <= len && vl >= 66) {
                    auto d = rec.data()+pos+vo;
                    auto n = std::to_integer<unsigned char>(d[64]);
                    if (66u + 2u*unsigned(n) <= vl) name = utf16le(d+66, n);
                }
            }

            if (type == 0x80) {
                data_found = true;
                if (!nonres) {
                    auto vl = le32(rec.data()+pos+16);
                    auto vo = le16(rec.data()+pos+20);
                    size = vl;
                    if (vo + vl <= len && vl) {
                        exts.push_back({0, mft_off + id*rec_size + pos + vo, vl});
                    }
                } else {
                    size = le64(rec.data()+pos+48);
                    auto roff = le16(rec.data()+pos+32);
                    auto rl = le16(rec.data()+pos+34);
                    if (roff + rl <= len) {
                        std::vector<Run> runs;
                        if (parse_runs(rec.data()+pos+roff, rl, runs)) {
                            std::uint64_t logical = 0;
                            for (const auto& r : runs) {
                                if (r.lcn != 0) {
                                    exts.push_back({logical, fs.offset + r.lcn*cluster, r.len*cluster});
                                }
                                logical += r.len*cluster;
                            }
                        }
                    }
                }
            }
            pos += len;
        }

        if (data_found && !exts.empty() && !name.empty()) {
            Candidate c{};
            c.id = out.size()+1;
            c.filesystem = FsType::NTFS;
            c.object_id = id;
            c.name = name;
            c.path = name;
            c.size = size;
            c.deleted = true;
            c.extents = std::move(exts);
            c.evidence = {
                {"NTFS_FILE_RECORD", "valid FILE record", 30},
                {"DELETED_FLAG", "MFT record not in-use", 30},
                {"NAME", "$FILE_NAME present", 15},
                {"DATA", "$DATA mapping present", 20}
            };
            c.confidence = 95;
            out.push_back(std::move(c));
        }
    }
    return true;
}
bool NtfsProvider::recover(ISource&src,const Candidate&c,const std::filesystem::path&dest,std::string&error,std::function<bool()>cancelled){
    std::error_code ec; std::filesystem::create_directories(dest, ec); if (ec) { error = "cannot create destination directory"; return false; }
    std::string safe=c.name; for(char& ch:safe) { if(ch=='/'||ch=='\\') ch='_'; }
    std::filesystem::path name=safe;
    auto outp=dest/name; std::ofstream out(outp,std::ios::binary); if(!out){error="cannot create destination";return false;}
    std::vector<std::byte> buf(1024*1024);
    std::uint64_t remaining=c.size;
    for(auto&e:c.extents){if(!remaining)break;if(cancelled&&cancelled()){error="cancelled";return false;}auto n=std::min<std::uint64_t>(remaining,e.length);std::uint64_t done=0;while(done<n){auto chunk=std::min<std::uint64_t>(buf.size(),n-done);if(!src.read_at(e.physical_offset+done,std::span<std::byte>(buf.data(),static_cast<size_t>(chunk)))){error="source read failed";return false;}out.write(reinterpret_cast<const char*>(buf.data()),static_cast<std::streamsize>(chunk));if(!out){error="destination write failed";return false;}done+=chunk;}remaining-=n;}
    if(remaining){error="extent map shorter than file size";return false;} return true;
}
}
