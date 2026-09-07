#pragma once
#include "forensic/types.hpp"
#include <string>
namespace forensic {
bool save_case(const Case&,const std::string&);
bool load_case(const std::string&,Case&);
bool init_case(const std::string&,const std::string&,const std::string&,Case&,std::string&);
bool append_event(Case&,const std::string&,const std::string&,const std::string&);
}
