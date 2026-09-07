#include "fragment/source.hpp"
#include "fragment/signatures.hpp"
#include "fragment/chains.hpp"
#include <cassert>
#include <vector>
#include <cstring>
class Mem:public frag::ISource{std::vector<std::byte>d;public:Mem(size_t n):d(n){}bool read_at(std::uint64_t o,std::span<std::byte>b)override{if(o>d.size()||b.size()>d.size()-o)return false;std::copy(d.begin()+o,d.begin()+o+b.size(),b.begin());return true;}std::uint64_t size()const override{return d.size();}auto&data(){return d;}};
int main(){Mem m(32768);auto&d=m.data();std::memcpy(d.data()+4096,"%PDF-",5);std::memcpy(d.data()+12288,"%PDF-",5);auto f=frag::find_anchors(m,frag::FileType::PDF,4096,m.size());assert(f.size()==2);auto e=frag::build_edges(m,f,4096);auto c=frag::build_chains(f,e,8);assert(!c.empty());return 0;}
