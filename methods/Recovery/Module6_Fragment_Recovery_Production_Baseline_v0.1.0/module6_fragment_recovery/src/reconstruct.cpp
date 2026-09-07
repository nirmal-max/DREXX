#include "fragment/reconstruct.hpp"
#include <fstream>
#include <filesystem>
#include <algorithm>
namespace frag{
bool recover(ISource&s,const Chain&c,const std::vector<Fragment>&fs,const std::string&dest,std::string&e){std::error_code ec;std::filesystem::create_directories(dest,ec);if(ec){e="cannot create destination";return false;}auto path=std::filesystem::path(dest)/("fragment_"+std::to_string(c.id)+"_"+name(c.type));std::ofstream o(path,std::ios::binary);if(!o){e="cannot create output";return false;}for(auto id:c.fragments){auto it=std::find_if(fs.begin(),fs.end(),[&](auto&q){return q.id==id;});if(it==fs.end()){e="fragment missing";return false;}std::vector<std::byte>b((size_t)it->length);if(!s.read_at(it->physical,b)){e="source read failed";return false;}o.write((char*)b.data(),(std::streamsize)b.size());if(!o){e="destination write failed";return false;}}return true;}
}
