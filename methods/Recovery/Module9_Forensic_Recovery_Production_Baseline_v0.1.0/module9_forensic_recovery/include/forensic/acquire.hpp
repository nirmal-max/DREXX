#pragma once
#include "forensic/types.hpp"
#include <string>
namespace forensic {
bool acquire_file(const std::string&,const std::string&,std::uint64_t&,std::string&);
HashResult hash_file(const std::string&);
}
