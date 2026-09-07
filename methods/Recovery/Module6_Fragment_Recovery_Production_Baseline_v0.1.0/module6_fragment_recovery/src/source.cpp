#include "fragment/source.hpp"
#include <fstream>
namespace frag{
class File final:public ISource{std::ifstream f;std::uint64_t n{};public:File(const std::string&p,std::string&e){f.open(p,std::ios::binary);if(!f){e="cannot open source";return;}f.seekg(0,std::ios::end);auto x=f.tellg();if(x<0){e="cannot size source";return;}n=(std::uint64_t)x;f.seekg(0);}bool read_at(std::uint64_t o,std::span<std::byte>b)override{if(o>n||b.size()>n-o)return false;f.clear();f.seekg((std::streamoff)o);f.read((char*)b.data(),(std::streamsize)b.size());return f.gcount()==(std::streamsize)b.size();}std::uint64_t size()const override{return n;}};
std::unique_ptr<ISource> open_source(const std::string&p,std::string&e){auto x=std::make_unique<File>(p,e);return e.empty()?std::move(x):nullptr;}
}
