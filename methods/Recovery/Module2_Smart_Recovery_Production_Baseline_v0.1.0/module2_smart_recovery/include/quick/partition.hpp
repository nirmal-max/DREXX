#pragma once
#include "quick/source.hpp"
#include "quick/types.hpp"
#include <vector>
namespace quick { std::vector<Partition> analyze_partitions(ISource& src, std::vector<std::string>& warnings); }
