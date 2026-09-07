#include "deep/source.hpp"
#include "deep/types.hpp"
#include <array>
#include <cstring>
namespace deep{
static std::uint16_t u16(const std::byte*p){return (std::uint16_t)std::to_integer<unsigned char>(p[0])|((std::uint16_t)std::to_integer<unsigned char>(p[1])<<8);}
static std::uint32_t u32(const std::byte*p){return (std::uint32_t)std::to_integer<unsigned char>(p[0])|((std::uint32_t)std::to_integer<unsigned char>(p[1])<<8)|((std::uint32_t)std::to_integer<unsigned char>(p[2])<<16)|((std::uint32_t)std::to_integer<unsigned char>(p[3])<<24);}
static std::uint64_t u64(const std::byte*p){std::uint64_t x=0;for(int i=0;i<8;i++)x|=(std::uint64_t)std::to_integer<unsigned char>(p[i])<<(8*i);return x;}
static void add(Candidate&c,const char*k,double w,const std::string&d){c.evidence.push_back({k,w,d});c.score+=w;}
std::vector<Candidate> detect_at(ISource&s,std::uint64_t off){
 std::array<std::byte,4096>b{};std::vector<Candidate>v;if(!s.read_at(off,b))return v;
 if(std::memcmp(b.data()+3,"NTFS    ",8)==0){auto bs=u16(b.data()+11);auto spc=std::to_integer<unsigned char>(b[13]);if(bs>=256&&bs<=4096&&(bs&(bs-1))==0&&spc&&spc<=128){Candidate c{};c.type=FsType::NTFS;c.offset=off;c.sector_size=bs;c.cluster_size=(std::uint64_t)bs*spc;add(c,"boot",35,"NTFS OEM");if(c.cluster_size<=1024*1024)add(c,"geometry",20,"valid cluster size");auto mft=u64(b.data()+48);if(mft<((s.size()-off)/c.cluster_size))add(c,"metadata",25,"$MFT LCN in bounds");else c.evidence.push_back({"metadata",0,"$MFT LCN out of bounds"});c.status="validated";v.push_back(c);}}
 if(std::memcmp(b.data()+3,"EXFAT   ",8)==0){auto bs=1u<<std::to_integer<unsigned char>(b[108]);auto cs=bs*(1u<<std::to_integer<unsigned char>(b[109]));auto heap=u32(b.data()+88),cl=u32(b.data()+92);if(bs>=512&&bs<=4096&&cs<=32*1024*1024&&heap>=32&&cl>0){Candidate c{};c.type=FsType::exFAT;c.offset=off;c.sector_size=bs;c.cluster_size=cs;c.declared_size=(std::uint64_t)(heap+cl)*bs;add(c,"boot",35,"exFAT OEM");add(c,"geometry",25,"valid shifts");if(c.declared_size<=s.size()-off)add(c,"bounds",25,"cluster heap fits source");c.status="validated";v.push_back(c);}}
 auto fat=b.data();if(std::to_integer<unsigned char>(fat[510])==0x55&&std::to_integer<unsigned char>(fat[511])==0xAA){auto bs=u16(b.data()+11);auto spc=std::to_integer<unsigned char>(b[13]);auto res=u16(b.data()+14);auto nf=std::to_integer<unsigned char>(b[16]);auto f16=u16(b.data()+22);auto f32=u32(b.data()+36);auto fs=(std::uint64_t)(f16?f16:f32);auto total=u16(b.data()+19);if(!total)total=u32(b.data()+32);if(bs>=512&&bs<=4096&&spc&&nf>=1&&nf<=8&&res){auto first=(std::uint64_t)res+nf*fs;auto clusters=first<total?(total-first)/spc:0;if(clusters>=10){Candidate c{};c.type=FsType::FAT;c.offset=off;c.sector_size=bs;c.cluster_size=(std::uint64_t)bs*spc;c.declared_size=(std::uint64_t)total*bs;add(c,"boot",30,"FAT BPB");add(c,"geometry",25,"plausible FAT geometry");if(c.declared_size<=s.size()-off)add(c,"bounds",20,"volume fits source");c.status="validated";v.push_back(c);}}}
 if(u16(b.data()+0x38)==0xEF53){auto bs=1024u<<u32(b.data()+24);auto bpc=(std::uint64_t)bs<<u32(b.data()+88);auto blocks=u64(b.data()+4);if(bs>=1024&&bs<=65536&&bpc>=bs&&bpc<=16*1024*1024&&blocks){Candidate c{};c.type=FsType::EXT;c.offset=off;c.sector_size=bs;c.cluster_size=bpc;c.declared_size=blocks*bs;add(c,"superblock",40,"EXT magic");add(c,"geometry",20,"valid block geometry");if(c.declared_size<=s.size()-off)add(c,"bounds",25,"block count fits source");c.status="validated";v.push_back(c);}}
 return v;
}
}
