#include "deep/scanner.hpp"
#include "deep/json.hpp"
#include <cassert>
#include <vector>
#include <cstring>
class Mem:public deep::ISource{std::vector<std::byte>d;public:Mem(size_t n):d(n){}bool read_at(std::uint64_t o,std::span<std::byte>b)override{if(o>d.size()||b.size()>d.size()-o)return false;std::copy(d.begin()+o,d.begin()+o+b.size(),b.begin());return true;}std::uint64_t size()const override{return d.size();}auto&data(){return d;}};
int main(){Mem m(2*1024*1024);auto&d=m.data();std::memcpy(d.data()+1000+3,"NTFS    ",8);d[1000+11]=std::byte(0);d[1000+12]=std::byte(2);d[1000+13]=std::byte(8);auto r=deep::scan(m,{0,m.size(),1024});assert(!r.candidates.empty());assert(r.candidates[0].type==deep::FsType::NTFS);assert(r.candidates[0].score>=55);return 0;}
