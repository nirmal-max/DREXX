#include "fsrecover/providers.hpp"
#include <array>
#include <cstring>
#include <algorithm>
namespace fsr {
static std::uint16_t u16(const std::byte*p){return std::uint16_t(std::to_integer<unsigned char>(p[0]))|(std::uint16_t(std::to_integer<unsigned char>(p[1]))<<8);}
static std::uint32_t u32(const std::byte*p){return std::uint32_t(std::to_integer<unsigned char>(p[0]))|(std::uint32_t(std::to_integer<unsigned char>(p[1]))<<8)|(std::uint32_t(std::to_integer<unsigned char>(p[2]))<<16)|(std::uint32_t(std::to_integer<unsigned char>(p[3]))<<24);}
static std::uint64_t u64(const std::byte*p){std::uint64_t x=0;for(int i=0;i<8;i++)x|=std::uint64_t(std::to_integer<unsigned char>(p[i]))<<(8*i);return x;}
static std::string utf16(const std::byte*p,size_t n){std::string s;for(size_t i=0;i<n;i++){auto u=u16(p+2*i);if(u<128)s.push_back(char(u));else if(u<2048){s.push_back(char(0xC0|(u>>6)));s.push_back(char(0x80|(u&63)));}else{s.push_back(char(0xE0|(u>>12)));s.push_back(char(0x80|((u>>6)&63)));s.push_back(char(0x80|(u&63)));}}return s;}
struct Run{std::uint64_t lcn,len;};
static bool runs(const std::byte*p,size_t n,std::vector<Run>&o){size_t i=0;std::int64_t lcn=0;while(i<n){auto h=std::to_integer<unsigned char>(p[i++]);if(!h)break;auto ls=h&15,os=h>>4;if(!ls||ls>8||os>8||i+ls+os>n)return false;std::uint64_t len=0;for(unsigned j=0;j<ls;j++)len|=std::uint64_t(std::to_integer<unsigned char>(p[i+j]))<<(8*j);std::uint64_t raw=0;for(unsigned j=0;j<os;j++)raw|=std::uint64_t(std::to_integer<unsigned char>(p[i+ls+j]))<<(8*j);if(os&&std::to_integer<unsigned char>(p[i+ls+os-1])&0x80)raw|=(~0ULL)<<(8*os);lcn+=static_cast<std::int64_t>(raw);if(lcn<0)return false;o.push_back({static_cast<std::uint64_t>(lcn),len});i+=ls+os;}return !o.empty();}
static bool usa(std::vector<std::byte>&r,std::uint32_t sec){auto off=u16(r.data()+4),cnt=u16(r.data()+6);if(off+2ULL*cnt>r.size())return false;auto seq=u16(r.data()+off);for(unsigned i=1;i<cnt;i++){auto p=std::uint64_t(i)*sec-2;if(p+2>r.size()||u16(r.data()+p)!=seq)return false;std::memcpy(r.data()+p,r.data()+off+2*i,2);}return true;}
bool scan_ntfs(ISource&s,const Geometry&g,std::vector<FsObject>&o,Health&h,std::function<bool()>cancelled){
 std::array<std::byte,512>b{};if(!s.read_at(g.volume_offset,b))return false;std::uint16_t bps=u16(b.data()+11); std::uint8_t spc=std::to_integer<unsigned char>(b[13]);auto cluster=std::uint64_t(bps)*spc,mft=u64(b.data()+48);auto rs=static_cast<std::int8_t>(std::to_integer<unsigned char>(b[64]));auto rec=rs<0?(1ULL<<-rs):std::uint64_t(rs)*cluster;if(rec<512||rec>1024*1024)return false;auto mftoff=g.volume_offset+mft*cluster;auto max=std::min<std::uint64_t>(g.volume_size/rec,2'000'000);
 for(std::uint64_t id=0;id<max;id++){if(cancelled&&cancelled())return false;std::vector<std::byte>r(static_cast<size_t>(rec));if(!s.read_at(mftoff+id*rec,r))break;if(std::memcmp(r.data(),"FILE",4)!=0)continue;if(!usa(r,bps))continue;std::uint16_t flags=u16(r.data()+22); std::uint16_t ao=u16(r.data()+20);if(ao>=r.size())continue;FsObject x{};x.id=id;x.type=(flags&2)?ObjectType::Directory:ObjectType::File;x.deleted=(flags&1)==0;size_t p=ao;std::vector<Run>rr;while(p+16<=r.size()){std::uint32_t type=u32(r.data()+p); std::uint32_t len=u32(r.data()+p+4);if(type==0xFFFFFFFF)break;if(len<24||p+len>r.size())break;auto non=std::to_integer<unsigned char>(r[p+8]);if(type==0x30&&!non){std::uint16_t vo=u16(r.data()+p+20); std::uint32_t vl=u32(r.data()+p+16);if(vo+vl<=len&&vl>=66){auto d=r.data()+p+vo;auto n=std::to_integer<unsigned char>(d[64]);if(66+2*n<=vl)x.name=utf16(d+66,n);x.parent=u64(d)&0xFFFFFFFFFFFFULL;x.mtime=u64(d+24);x.ctime=u64(d+16);x.atime=u64(d+32);}}
 if(type==0x80){if(!non){std::uint16_t vo=u16(r.data()+p+20); std::uint32_t vl=u32(r.data()+p+16);x.size=vl;if(vo+vl<=len&&vl)x.extents.push_back({0,mftoff+id*rec+p+vo,vl});}else{std::uint16_t ro=u16(r.data()+p+32); std::uint16_t rl=u16(r.data()+p+34);x.size=u64(r.data()+p+48);if(ro+rl<=len&&runs(r.data()+p+ro,rl,rr)){std::uint64_t logical=0;for(auto&q:rr){if(q.lcn){x.extents.push_back({logical,g.volume_offset+q.lcn*cluster,q.len*cluster});}logical+=q.len*cluster;}}}}
 p+=len;}
 if(!x.name.empty()&&!x.extents.empty())o.push_back(std::move(x));
 }
 h.score=90;h.checks.push_back("NTFS boot geometry");h.checks.push_back("MFT FILE signatures");h.checks.push_back("USA fixup validation");h.checks.push_back("attribute bounds");return true;
}
}
