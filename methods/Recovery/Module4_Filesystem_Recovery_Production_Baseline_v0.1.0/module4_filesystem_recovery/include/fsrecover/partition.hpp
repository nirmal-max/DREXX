#pragma once
#include "fsrecover/source.hpp"
#include "fsrecover/types.hpp"
#include <vector>
namespace fsr { std::vector<Partition> analyze_partitions(ISource&,std::vector<std::string>&); }
