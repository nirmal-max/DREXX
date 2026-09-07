#include "quick/filesystem.hpp"
#include <array>
#include <cstring>
namespace quick {
static std::uint16_t le16(const std::byte* p){return std::uint16_t(std::to_integer<unsigned char>(p[0]))|(std::uint16_t(std::to_integer<unsigned char>(p[1]))<<8);}
static std::uint32_t le32(const std::byte* p){return std::uint32_t(std::to_integer<unsigned char>(p[0]))|(std::uint32_t(std::to_integer<unsigned char>(p[1]))<<8)|(std::uint32_t(std::to_integer<unsigned char>(p[2]))<<16)|(std::uint32_t(std::to_integer<unsigned char>(p[3]))<<24);}
FsContext detect_filesystem(ISource& src,const Partition&p){
    FsContext c{}; c.offset=p.offset;c.size=p.size;
    std::array<std::byte,4096> b{}; if(!src.read_at(p.offset,b)) return c;
    if(std::memcmp(b.data()+3,"NTFS    ",8)==0 && le16(b.data()+11)>=512) { c.type=FsType::NTFS;c.sector_size=le16(b.data()+11);return c; }
    if(std::memcmp(b.data()+3,"EXFAT   ",8)==0 && le16(b.data()+11)>=512) { c.type=FsType::exFAT;c.sector_size=1u<<std::to_integer<unsigned char>(b[108]);return c; }
    if(std::memcmp(b.data()+82,"FAT32   ",8)==0 || std::memcmp(b.data()+54,"FAT16   ",8)==0 || std::memcmp(b.data()+54,"FAT12   ",8)==0) {
        auto spc=std::to_integer<unsigned char>(b[13]); auto bps=le16(b.data()+11);
        if(spc && bps>=512) { c.sector_size=bps; auto total16=le16(b.data()+19); auto total32=le32(b.data()+32); auto total=total16?total16:total32; auto fatsz16=le16(b.data()+22); auto fatsz32=le32(b.data()+36); auto fatsz=fatsz16?fatsz16:fatsz32; auto root=le16(b.data()+17); auto data=total-(le16(b.data()+14)+std::to_integer<unsigned char>(b[16])*fatsz+(root*32+bps-1)/bps); auto clusters=data/spc; c.type=clusters<4085?FsType::FAT12:(clusters<65525?FsType::FAT16:FsType::FAT32); return c; }
    }
    return c;
}
}
