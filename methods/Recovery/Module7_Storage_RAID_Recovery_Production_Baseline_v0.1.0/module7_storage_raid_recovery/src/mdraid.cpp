#include "raid/source.hpp"
#include <array>
#include <cstring>
namespace raid {
bool detect_mdraid_superblock(ISource&s,std::string&detail){std::array<std::byte,4096>b{};if(s.size()<4096)return false;if(!s.read_at(s.size()-4096,b))return false;for(size_t i=0;i+4<=b.size();i++)if(std::memcmp(b.data()+i,"md",2)==0){detail="possible md metadata marker";return true;}return false;}
}
