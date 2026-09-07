#include <algorithm>
#include "fsrecover/providers.hpp"
#include <array>
#include <cstring>
namespace fsr {
static std::uint16_t u16(const std::byte*p){return std::uint16_t(std::to_integer<unsigned char>(p[0]))|(std::uint16_t(std::to_integer<unsigned char>(p[1]))<<8);}
static std::uint32_t u32(const std::byte*p){return std::uint32_t(std::to_integer<unsigned char>(p[0]))|(std::uint32_t(std::to_integer<unsigned char>(p[1]))<<8)|(std::uint32_t(std::to_integer<unsigned char>(p[2]))<<16)|(std::uint32_t(std::to_integer<unsigned char>(p[3]))<<24);}
static std::uint64_t u64(const std::byte*p){std::uint64_t x=0;for(int i=0;i<8;i++)x|=std::uint64_t(std::to_integer<unsigned char>(p[i]))<<(8*i);return x;}
bool scan_ext(ISource&s,const Geometry&g,std::vector<FsObject>&o,Health&h,std::function<bool()>cancelled){
 std::uint64_t sb=g.volume_offset+1024;std::array<std::byte,1024>b{};if(!s.read_at(sb,b))return false;if(u16(b.data()+56)!=0xEF53)return false;std::uint32_t bs=1024u<<u32(b.data()+24); std::uint64_t bpc=std::uint64_t(bs)<<u32(b.data()+88); std::uint32_t inodes=u32(b.data()); std::uint32_t ipg=u32(b.data()+40); std::uint16_t it=u16(b.data()+0x58);if(!bs||!bpc||!ipg||!it)return false;auto groups=(inodes+ipg-1)/ipg;groups=std::min<std::uint64_t>(groups,65536);
 for(std::uint64_t gr=0;gr<groups;gr++){if(cancelled&&cancelled())return false;std::vector<std::byte>gd(64);auto gd_off=g.volume_offset+std::uint64_t(bs==1024?2:1)*bs+gr*64;if(!s.read_at(gd_off,gd))break;auto inode_table=u32(gd.data()+8);auto base=g.volume_offset+std::uint64_t(inode_table)*bs;for(std::uint32_t n=0;n<ipg;n++){if(o.size()>500000)return true;std::vector<std::byte>in(static_cast<size_t>(it));if(!s.read_at(base+std::uint64_t(n)*it,in))break;auto mode=u16(in.data());if(!mode)continue;auto flags=u32(in.data()+32);FsObject x{};x.id=gr*ipg+n+1;x.type=(mode&0x4000)?ObjectType::Directory:ObjectType::File;x.size=u32(in.data()+4);if(it>=0x80)x.size|=u64(in.data()+0x70)<<32;x.mtime=u32(in.data()+0x44);x.ctime=u32(in.data()+0x48);x.atime=u32(in.data()+0x40);
  auto ptrs=reinterpret_cast<const std::byte*>(in.data()+40);for(int i=0;i<12;i++){auto blk=u32(ptrs+i*4);if(!blk)break;x.extents.push_back({std::uint64_t(i)*bs,g.volume_offset+std::uint64_t(blk)*bs,bs});}if(!x.extents.empty())o.push_back(std::move(x));
 }}h.score=65;h.checks.push_back("EXT superblock magic");h.checks.push_back("block-group descriptor bounds");h.checks.push_back("inode-table traversal");h.warnings.push_back("EXT baseline enumerates direct inode blocks; full extent-tree and directory parser are release gates");return true;
}
}
