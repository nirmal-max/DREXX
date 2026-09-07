
#include "fsrecover/partition.hpp"
#include <array>
#include <cstring>
#include <algorithm>
namespace fsr {
static std::uint32_t u32(const std::byte*p){return std::uint32_t(std::to_integer<unsigned char>(p[0]))|(std::uint32_t(std::to_integer<unsigned char>(p[1]))<<8)|(std::uint32_t(std::to_integer<unsigned char>(p[2]))<<16)|(std::uint32_t(std::to_integer<unsigned char>(p[3]))<<24);}
static std::uint64_t u64(const std::byte*p){std::uint64_t x=0;for(int i=0;i<8;i++)x|=std::uint64_t(std::to_integer<unsigned char>(p[i]))<<(8*i);return x;}
std::vector<Partition> analyze_partitions(ISource&s,std::vector<std::string>&w){
 std::vector<Partition>o;std::array<std::byte,512>b{};if(!s.read_at(0,b)){w.push_back("partition table unreadable");return o;}
 if(std::to_integer<unsigned char>(b[510])==0x55&&std::to_integer<unsigned char>(b[511])==0xAA){
  bool g=false;
  for(int i=0;i<4;i++){
   auto e=b.data()+446+i*16;auto t=std::to_integer<unsigned char>(e[4]);if(t==0xEE)g=true;
   if(t){Partition p{};p.index=i+1;p.offset=std::uint64_t(u32(e+8))*512;p.size=std::uint64_t(u32(e+12))*512;p.type="MBR:"+std::to_string(t);if(p.offset<s.size()&&p.size<=s.size()-p.offset)o.push_back(p);}
  }
  if(g){
   std::array<std::byte,512>h{};
   if(s.read_at(512,h)&&std::memcmp(h.data(),"EFI PART",8)==0){
    auto lba=u64(h.data()+72);auto cnt=u32(h.data()+80);auto esz=u32(h.data()+84);
    if(esz>=128&&esz<=4096&&cnt<=4096){
     std::vector<std::byte>e(esz);o.clear();
     for(std::uint32_t i=0;i<cnt;i++){
      auto off=lba*512ULL+std::uint64_t(i)*esz;if(off>s.size()||esz>s.size()-off)break;if(!s.read_at(off,e))break;
      bool z=true;for(int j=0;j<16;j++)if(e[j]!=std::byte{}){z=false;break;}if(z)continue;
      auto first=u64(e.data()+32);auto last=u64(e.data()+40);if(last<first)continue;
      Partition p{};p.index=i+1;p.offset=first*512ULL;p.size=(last-first+1)*512ULL;p.type="GPT";
      if(p.offset<s.size()&&p.size<=s.size()-p.offset)o.push_back(p);
     }
    }
   }
  }
 }
 if(o.empty()){Partition p{};p.index=0;p.offset=0;p.size=s.size();p.type="WHOLE_SOURCE";o.push_back(p);}
 return o;
}
}
