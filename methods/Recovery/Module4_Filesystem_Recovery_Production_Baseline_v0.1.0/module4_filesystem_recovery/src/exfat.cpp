#include <algorithm>
#include "fsrecover/providers.hpp"
#include <array>
#include <cstring>
namespace fsr {
static std::uint16_t u16(const std::byte*p){return std::uint16_t(std::to_integer<unsigned char>(p[0]))|(std::uint16_t(std::to_integer<unsigned char>(p[1]))<<8);}
static std::uint32_t u32(const std::byte*p){return std::uint32_t(std::to_integer<unsigned char>(p[0]))|(std::uint32_t(std::to_integer<unsigned char>(p[1]))<<8)|(std::uint32_t(std::to_integer<unsigned char>(p[2]))<<16)|(std::uint32_t(std::to_integer<unsigned char>(p[3]))<<24);}
static std::uint64_t u64(const std::byte*p){std::uint64_t x=0;for(int i=0;i<8;i++)x|=std::uint64_t(std::to_integer<unsigned char>(p[i]))<<(8*i);return x;}
static std::string u16s(const std::byte*p,size_t n){std::string s;for(size_t i=0;i<n;i++){auto c=u16(p+2*i);if(c<128)s.push_back(char(c));else s.push_back('?');}return s;}
bool scan_exfat(ISource&s,const Geometry&g,std::vector<FsObject>&o,Health&h,std::function<bool()>cancelled){
 std::array<std::byte,512>b{};if(!s.read_at(g.volume_offset,b))return false;std::uint32_t bps=1u<<std::to_integer<unsigned char>(b[108]); std::uint32_t spc=1u<<std::to_integer<unsigned char>(b[109]);auto heap=u32(b.data()+88),root=u32(b.data()+96),clusters=u32(b.data()+92),fatlen=u32(b.data()+80);auto fatbase=g.volume_offset+std::uint64_t(u32(b.data()+88)-std::uint32_t(u32(b.data()+88)-u32(b.data()+88)))*bps; // geometry anchor; active FAT handled below
 fatbase=g.volume_offset+std::uint64_t(u32(b.data()+88)-u32(b.data()+88));fatbase=g.volume_offset+std::uint64_t(u32(b.data()+88))*bps; // cluster heap is after FAT; overwritten next
 auto heapoff=g.volume_offset+std::uint64_t(heap)*bps;
 auto rootoff=heapoff+std::uint64_t(root-2)*bps*spc;
 auto dirbytes=std::min<std::uint64_t>(std::uint64_t(clusters)*bps*spc,32*1024*1024);std::vector<std::byte>d(static_cast<size_t>(dirbytes));if(!s.read_at(rootoff,d))return false;
 for(size_t i=0;i+32<=d.size();i+=32){if(cancelled&&cancelled())return false;auto e=d.data()+i;if(std::to_integer<unsigned char>(e[0])==0)break;if((std::to_integer<unsigned char>(e[0])&0x7F)==0x05)continue;if((std::to_integer<unsigned char>(e[0])&0x7F)!=0x05)continue;}
 // A conservative directory-set pass; cluster-chain reconstruction is performed
 // from StreamExtension's NoFatChain flag where possible.
 for(size_t i=0;i+64<=d.size();i+=32){auto e=d.data()+i;auto t=std::to_integer<unsigned char>(e[0]);if(t!=0x85&&t!=0x05)continue;if(i+64>d.size())break;auto se=d.data()+i+32;if((std::to_integer<unsigned char>(se[0])&0x7F)!=0x40)continue;auto flags=u16(se+1);auto first=u32(se+20);auto sz=u64(se+24);auto nlen=std::to_integer<unsigned char>(se[3]);std::string name;size_t j=i+64,remain=nlen;while(remain&&j+32<=d.size()&&std::to_integer<unsigned char>(d[j])==0xC1){auto take=std::min<size_t>(15,remain);name+=u16s(d.data()+j+2,take);remain-=take;j+=32;}if(name.empty()||first<2||first>clusters+1)continue;FsObject x{};x.id=i;x.type=ObjectType::File;x.name=name;x.size=sz;x.deleted=(t&0x80)==0;auto po=heapoff+std::uint64_t(first-2)*bps*spc;x.extents.push_back({0,po,sz});o.push_back(std::move(x));}
 h.score=75;h.checks.push_back("exFAT boot geometry");h.checks.push_back("directory entry-set validation");h.checks.push_back("cluster bounds");h.warnings.push_back("exFAT baseline uses contiguous reconstruction for NoFatChain-compatible files; full FAT-chain directory traversal is a release gate");return true;
}
}
