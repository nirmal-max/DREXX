#include <algorithm>
#include "fsrecover/providers.hpp"
#include <array>
#include <cstring>
namespace fsr {
static std::uint16_t u16(const std::byte*p){return std::uint16_t(std::to_integer<unsigned char>(p[0]))|(std::uint16_t(std::to_integer<unsigned char>(p[1]))<<8);}
static std::uint32_t u32(const std::byte*p){return std::uint32_t(std::to_integer<unsigned char>(p[0]))|(std::uint32_t(std::to_integer<unsigned char>(p[1]))<<8)|(std::uint32_t(std::to_integer<unsigned char>(p[2]))<<16)|(std::uint32_t(std::to_integer<unsigned char>(p[3]))<<24);}
static std::uint32_t fatval(const std::vector<std::byte>&f,std::uint32_t c,FsType t){auto bits=t==FsType::FAT32?32:(t==FsType::FAT16?16:12);if(bits==12){auto x=std::uint32_t(f[c*3/2])|std::uint32_t(std::to_integer<unsigned char>(f[c*3/2+1]))<<8;return c&1?x>>4:x&0xFFF;}if(bits==16)return u16(f.data()+c*2);return u32(f.data()+c*4)&0x0FFFFFFF;}
bool scan_fat(ISource&s,const Geometry&g,std::vector<FsObject>&o,Health&h,std::function<bool()>cancelled){
 std::array<std::byte,512>b{};if(!s.read_at(g.volume_offset,b))return false;std::uint16_t bps=u16(b.data()+11); std::uint8_t spc=std::to_integer<unsigned char>(b[13]); std::uint16_t reserved=u16(b.data()+14); std::uint8_t fats=std::to_integer<unsigned char>(b[16]); std::uint16_t f16=u16(b.data()+22); std::uint32_t f32=u32(b.data()+36); std::uint32_t fatsz=f16?f16:f32; std::uint16_t root=u16(b.data()+17); std::uint32_t total=u16(b.data()+19);if(!total)total=u32(b.data()+32);auto rootsec=(std::uint64_t(root)*32+bps-1)/bps;auto first=std::uint64_t(reserved)+std::uint64_t(fats)*fatsz+rootsec;auto clusters=(total-first)/spc;if(!bps||!spc||!fatsz)return false;auto fatbytes=std::uint64_t(fatsz)*bps;if(fatbytes>64*1024*1024)return false;std::vector<std::byte>fat(static_cast<size_t>(fatbytes));if(!s.read_at(g.volume_offset+std::uint64_t(reserved)*bps,fat))return false;
 std::uint64_t dirsec=clusters>=65525?first:(std::uint64_t(reserved)+std::uint64_t(fats)*fatsz);std::uint64_t dirbytes=clusters>=65525?std::uint64_t(spc)*bps*std::min<std::uint64_t>(clusters,4096):rootsec*bps;dirbytes=std::min<std::uint64_t>(dirbytes,32*1024*1024);std::vector<std::byte>d(static_cast<size_t>(dirbytes));if(!s.read_at(g.volume_offset+dirsec*bps,d))return false;
 std::string lfn;
 for(size_t i=0;i+32<=d.size();i+=32){if(cancelled&&cancelled())return false;auto e=d.data()+i;auto t=std::to_integer<unsigned char>(e[0]);if(t==0)break;if(t==0xE5){lfn.clear();continue;}if(t==0x0F){std::string z;for(int k=1;k<32;k+=2){auto c=u16(e+k);if(c&&c!=0xFFFF)z.push_back(c<128?char(c):'?');}lfn=z+lfn;continue;}auto attr=std::to_integer<unsigned char>(e[11]);if(attr&0x08)continue;auto cl=(std::uint32_t(u16(e+20))<<16)|u16(e+26);auto sz=u32(e+28);if(cl<2||cl>=clusters+2)continue;FsObject x{};x.id=i;x.parent=0;x.type=(attr&0x10)?ObjectType::Directory:ObjectType::File;x.name=lfn.empty()?std::string(reinterpret_cast<const char*>(e+0),0):lfn; if(x.name.empty()){for(int k=1;k<11;k++){char c=char(std::to_integer<unsigned char>(e[k]));if(c!=' ')x.name.push_back(c);}}x.size=sz;x.deleted=t==0xE5;
 std::uint32_t cur=cl;std::uint64_t logical=0;for(size_t guard=0;guard<clusters&&cur>=2&&cur<clusters+2;guard++){auto next=fatval(fat,cur,g.type);auto po=g.volume_offset+(first+std::uint64_t(cur-2)*spc)*bps;x.extents.push_back({logical,po,std::uint64_t(spc)*bps});logical+=std::uint64_t(spc)*bps;if(next>=0x0FFFFFF8u|| (g.type==FsType::FAT16&&next>=0xFFF8u)||(g.type==FsType::FAT12&&next>=0xFF8u))break;if(next==0||next==cur)break;cur=next;}
 if(!x.extents.empty())o.push_back(std::move(x));lfn.clear();
 }
 h.score=80;h.checks.push_back("FAT BPB geometry");h.checks.push_back("FAT chain traversal");h.checks.push_back("directory bounds");return true;
}
}
