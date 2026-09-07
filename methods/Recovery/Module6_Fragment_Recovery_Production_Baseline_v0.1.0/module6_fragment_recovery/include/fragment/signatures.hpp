#pragma once
#include "fragment/types.hpp"
#include "fragment/source.hpp"
#include <string>
namespace frag{FileType parse_type(const std::string&);std::vector<Fragment> find_anchors(ISource&,FileType,std::uint64_t,std::uint64_t);}
