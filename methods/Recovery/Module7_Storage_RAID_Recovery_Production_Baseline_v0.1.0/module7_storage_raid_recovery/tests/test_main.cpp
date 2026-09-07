#include "raid/layout.hpp"
#include <cassert>
#include <vector>
#include <fstream>
class Mem:public raid::ISource{std::vector<std::byte>d;public:Mem(size_t n):d(n){}bool read_at(std::uint64_t o,std::span<std::byte>b)override{if(o>d.size()||b.size()>d.size()-o)return false;std::copy(d.begin()+o,d.begin()+o+b.size(),b.begin());return true;}std::uint64_t size()const override{return d.size();}};
int main(){std::vector<raid::Member>m{{0,"a",8192,false},{1,"b",8192,false},{2,"c",8192,false},{3,"d",8192,false}};auto l=raid::make_layout(raid::Level::R5,8,m);assert(l.logical_size==24576);assert(l.stripe_sectors==8);return 0;}
