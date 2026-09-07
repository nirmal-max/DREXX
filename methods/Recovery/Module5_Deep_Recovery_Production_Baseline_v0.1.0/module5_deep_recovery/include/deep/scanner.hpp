#pragma once
#include "deep/source.hpp"
#include "deep/types.hpp"
#include <functional>
namespace deep{
Result scan(ISource&,ScanRegion,std::function<bool()> cancelled={});
bool save_state(const ScanState&,const std::string&);
bool load_state(const std::string&,ScanState&);
}
