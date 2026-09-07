#include "quick/filesystem.hpp"
#include "quick/source.hpp"
#include "quick/partition.hpp"
#include <cassert>
#include <fstream>
#include <vector>
#include <iostream>
#include <cstring>
#include <algorithm>

class MemSource final : public quick::ISource {
    std::vector<std::byte> d_;
public:
    explicit MemSource(size_t n):d_(n){}
    bool read_at(std::uint64_t o,std::span<std::byte> out) override {if(o> d_.size() || out.size()>d_.size()-o)return false;std::copy(d_.begin()+o,d_.begin()+o+out.size(),out.begin());return true;}
    std::uint64_t size()const override{return d_.size();}
    std::string identity()const override{return "memory";}
    std::vector<std::byte>& data(){return d_;}
};
static void put16(std::byte*p,std::uint16_t x){p[0]=std::byte(x&255);p[1]=std::byte(x>>8);}
static void put32(std::byte*p,std::uint32_t x){for(int i=0;i<4;i++)p[i]=std::byte((x>>(8*i))&255);}
int main(){
    {
        MemSource s(4096); auto&d=s.data();put16(d.data()+510,0xAA55);d[446+4]=std::byte(0x07);put32(d.data()+446+8,1);put32(d.data()+446+12,7);auto p=quick::analyze_partitions(s,*new std::vector<std::string>());assert(!p.empty());
    }
    {
        MemSource s(4096);auto&d=s.data();std::memcpy(d.data()+3,"NTFS    ",8);put16(d.data()+11,512);d[13]=std::byte(8);auto p=quick::Partition{1,0,4096,"test",""};auto fs=quick::detect_filesystem(s,p);assert(fs.type==quick::FsType::NTFS);assert(fs.sector_size==512);
    }
    {
        MemSource s(4096);auto&d=s.data();std::memcpy(d.data()+3,"EXFAT   ",8);put16(d.data()+11,512);d[108]=std::byte(0);d[109]=std::byte(3);auto p=quick::Partition{1,0,4096,"test",""};auto fs=quick::detect_filesystem(s,p);assert(fs.type==quick::FsType::exFAT);assert(fs.sector_size==512);
    }
    std::cout<<"all tests passed\n";
}
