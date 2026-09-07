#pragma once
#include "targeted/types.hpp"
#include "targeted/source.hpp"
#include <functional>
namespace targeted {
ScanResult scan(ISource&,const std::vector<Rule>&,std::uint64_t start=0,std::uint64_t length=0,
                std::function<bool()>cancelled={});
}
