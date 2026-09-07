#include "targeted/recovery.hpp"
#include <fstream>
#include <filesystem>
#include <algorithm>
namespace targeted {
bool recover(ISource&src,const Candidate&c,const std::string&dest,std::string&e,std::function<bool()>cancelled){
 if(c.size==0||c.offset>src.size()||c.size>src.size()-c.offset){e="candidate outside source";return false;}
 std::error_code ec;std::filesystem::create_directories(dest,ec);if(ec){e="cannot create destination";return false;}
 std::string safe=c.name;for(char&x:safe)if(x=='/'||x=='\\'||x==':'||x=='\0')x='_';
 std::ofstream o(std::filesystem::path(dest)/safe,std::ios::binary);if(!o){e="cannot create output";return false;}
 std::vector<std::byte>b(1024*1024);std::uint64_t done=0;while(done<c.size){if(cancelled&&cancelled()){e="cancelled";return false;}auto n=std::min<std::uint64_t>(b.size(),c.size-done);if(!src.read_at(c.offset+done,std::span<std::byte>(b.data(),static_cast<size_t>(n)))){e="source read failed";return false;}o.write(reinterpret_cast<const char*>(b.data()),static_cast<std::streamsize>(n));if(!o){e="destination write failed";return false;}done+=n;}return true;
}
}
