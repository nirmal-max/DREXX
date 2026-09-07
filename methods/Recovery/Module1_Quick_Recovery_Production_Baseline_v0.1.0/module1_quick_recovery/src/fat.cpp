#include "quick/fat.hpp"
#include <array>
#include <cstring>
#include <fstream>
namespace quick {
static std::uint16_t le16(const std::byte*p){return std::uint16_t(std::to_integer<unsigned char>(p[0]))|(std::uint16_t(std::to_integer<unsigned char>(p[1]))<<8);}
static std::uint32_t le32(const std::byte*p){return std::uint32_t(std::to_integer<unsigned char>(p[0]))|(std::uint32_t(std::to_integer<unsigned char>(p[1]))<<8)|(std::uint32_t(std::to_integer<unsigned char>(p[2]))<<16)|(std::uint32_t(std::to_integer<unsigned char>(p[3]))<<24);}
bool FatProvider::scan(ISource&src,const FsContext&fs,std::vector<Candidate>&out,std::vector<std::string>&w,std::function<bool()>cancelled){
    std::array<std::byte,512>b{};if(!src.read_at(fs.offset,b))return false;auto bps=le16(b.data()+11);auto spc=std::to_integer<unsigned char>(b[13]);auto reserved=le16(b.data()+14);auto fats=b[16];auto root=le16(b.data()+17);auto fatsz16=le16(b.data()+22);auto fatsz32=le32(b.data()+36);auto fatsz=fatsz16?fatsz16:fatsz32;auto rootclus=le32(b.data()+44);if(!bps||!spc||!fatsz){w.push_back("invalid FAT geometry");return false;}
    std::uint64_t root_dir_sectors=((std::uint64_t(root)*32)+bps-1)/bps;std::uint64_t first_data=reserved+std::uint64_t(fats)*fatsz+root_dir_sectors;std::uint64_t data_secs=fs.size/bps-first_data;std::uint64_t clusters=data_secs/spc;std::uint64_t root_first=(clusters>=65525?rootclus:0);
    std::uint64_t root_off;
    if(clusters>=65525) root_off=fs.offset+(first_data+(root_first-2)*spc)*bps;
    else root_off=fs.offset+(reserved+std::uint64_t(fats)*fatsz)*bps;
    std::uint64_t root_bytes=clusters>=65525?std::min<std::uint64_t>(fs.size-(root_off-fs.offset),16*1024*1024):root_dir_sectors*bps;
    std::vector<std::byte>d(static_cast<size_t>(root_bytes));if(!src.read_at(root_off,d))return false;
    for(size_t i=0;i+32<=d.size();i+=32){if(cancelled&&cancelled())return false;auto e=d.data()+i;auto first=std::to_integer<unsigned char>(e[0]);if(first==0x00)break;if(first==0xE5){auto attr=std::to_integer<unsigned char>(e[11]);if(attr==0x0F||attr&0x08)continue;std::string n;for(int j=1;j<11;j++){char c=char(std::to_integer<unsigned char>(e[j]));if(c!=' ')n.push_back(c);}auto hi=clusters>=65525?le16(e+20):0;auto lo=le16(e+26);auto cl=(std::uint32_t(hi)<<16)|lo;auto size=le32(e+28);if(!cl||!size)continue;auto po=fs.offset+(first_data+(std::uint64_t(cl)-2)*spc)*bps;Candidate c{};c.id=out.size()+1;c.filesystem=fs.type;c.object_id=i;c.name=n;c.path=n;c.size=size;c.deleted=true;c.extents={{0,po,size}};c.evidence={{"FAT_DIR_ENTRY","deleted directory entry",35},{"CLUSTER","valid first cluster",25},{"SIZE","directory size present",15}};c.confidence=75;out.push_back(std::move(c));}}
    return true;
}
bool FatProvider::recover(ISource&src,const Candidate&c,const std::filesystem::path&dest,std::string&error,std::function<bool()>cancelled){
    std::error_code ec;std::filesystem::create_directories(dest,ec);auto n=c.name;for(char&ch:n)if(ch=='/'||ch=='\\')ch='_';std::ofstream o(dest/n,std::ios::binary);if(!o){error="cannot create destination";return false;}std::vector<std::byte>b(1024*1024);std::uint64_t rem=c.size;for(auto&e:c.extents){auto x=std::min(rem,e.length);std::uint64_t done=0;while(done<x){if(cancelled&&cancelled()){error="cancelled";return false;}auto z=std::min<std::uint64_t>(b.size(),x-done);if(!src.read_at(e.physical_offset+done,std::span<std::byte>(b.data(),static_cast<size_t>(z)))){error="source read failed";return false;}o.write(reinterpret_cast<const char*>(b.data()),static_cast<std::streamsize>(z));done+=z;}rem-=x;}return rem==0;
}
}
