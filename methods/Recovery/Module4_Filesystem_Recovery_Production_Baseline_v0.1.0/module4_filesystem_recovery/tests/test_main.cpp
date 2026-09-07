#include <algorithm>
#include "fsrecover/detect.hpp"
#include "fsrecover/partition.hpp"
#include <vector>
#include <cassert>
#include <cstring>
#include <iostream>
class Mem: public fsr::ISource{
 std::vector<std::byte>d;
public:Mem(size_t n):d(n){}bool read_at(std::uint64_t o,std::span<std::byte>b)override{if(o>d.size()||b.size()>d.size()-o)return false;std::copy(d.begin()+o,d.begin()+o+b.size(),b.begin());return true;}std::uint64_t size()const override{return d.size();}std::string identity()const override{return"mem";}auto& data(){return d;}
};
static void p16(std::byte*p,std::uint16_t x){p[0]=std::byte(x);p[1]=std::byte(x>>8);}
int main(){
 Mem m(4096);std::memcpy(m.data().data()+3,"NTFS    ",8);p16(m.data().data()+11,512);m.data()[13]=std::byte(8);fsr::Partition p{1,0,4096,"test"};auto g=fsr::detect(m,p);assert(g.type==fsr::FsType::NTFS);assert(g.cluster_size==4096);
 auto ps=fsr::analyze_partitions(m,*new std::vector<std::string>());assert(!ps.empty());std::cout<<"all tests passed\n";
}
