#include "fsrecover/detect.hpp"
#include <array>
#include <cstring>
namespace fsr {
static std::uint16_t u16(const std::byte*p){return std::uint16_t(std::to_integer<unsigned char>(p[0]))|(std::uint16_t(std::to_integer<unsigned char>(p[1]))<<8);}
static std::uint32_t u32(const std::byte*p){return std::uint32_t(std::to_integer<unsigned char>(p[0]))|(std::uint32_t(std::to_integer<unsigned char>(p[1]))<<8)|(std::uint32_t(std::to_integer<unsigned char>(p[2]))<<16)|(std::uint32_t(std::to_integer<unsigned char>(p[3]))<<24);}
Geometry detect(ISource&s,const Partition&p){
 Geometry g{};g.volume_offset=p.offset;g.volume_size=p.size;std::array<std::byte,4096>b{};if(!s.read_at(p.offset,b))return g;
 if(std::memcmp(b.data()+3,"NTFS    ",8)==0){g.type=FsType::NTFS;g.sector_size=u16(b.data()+11);g.cluster_size=g.sector_size*std::to_integer<unsigned char>(b[13]);g.metadata_offset=p.offset;return g;}
 if(std::memcmp(b.data()+3,"EXFAT   ",8)==0){g.type=FsType::exFAT;g.sector_size=1u<<std::to_integer<unsigned char>(b[108]);g.cluster_size=g.sector_size*(1u<<std::to_integer<unsigned char>(b[109]));g.metadata_offset=p.offset;return g;}
 if(std::memcmp(b.data()+54,"FAT16   ",8)==0||std::memcmp(b.data()+82,"FAT32   ",8)==0||std::memcmp(b.data()+54,"FAT12   ",8)==0){
  std::uint8_t spc=std::to_integer<unsigned char>(b[13]); std::uint16_t bps=u16(b.data()+11); std::uint16_t reserved=u16(b.data()+14); std::uint8_t fats=std::to_integer<unsigned char>(b[16]); std::uint16_t f16=u16(b.data()+22); std::uint32_t f32=u32(b.data()+36); std::uint32_t fs=f16?f16:f32; std::uint16_t root=u16(b.data()+17); std::uint32_t total=u16(b.data()+19); if(!total)total=u32(b.data()+32); auto rootsec=(std::uint64_t(root)*32+bps-1)/bps; auto first=std::uint64_t(reserved)+std::uint64_t(fats)*fs+rootsec; auto clusters=(std::uint64_t(total)-first)/spc; g.type=clusters<4085?FsType::FAT12:(clusters<65525?FsType::FAT16:FsType::FAT32); g.sector_size=bps; g.cluster_size=bps*spc; g.metadata_offset=p.offset; return g;}
 if(u16(b.data()+0x38)==0xEF53){std::uint32_t log_bs=u32(b.data()+24); g.sector_size=1024u<<log_bs; g.cluster_size=1024u<<u32(b.data()+88); std::uint16_t rev_minor=u16(b.data()+62); std::uint32_t feat=u32(b.data()+96); g.type=(feat&0x40)?FsType::EXT4:FsType::EXT3;g.metadata_offset=p.offset;return g;}
 return g;
}
}
