#pragma once
#include "fragment/types.hpp"
#include "fragment/source.hpp"
#include <vector>
namespace frag{std::vector<Edge> build_edges(ISource&,const std::vector<Fragment>&,std::uint64_t);std::vector<Chain> build_chains(const std::vector<Fragment>&,const std::vector<Edge>&,std::uint64_t);}
