#pragma once
#include "targeted/types.hpp"
#include "targeted/source.hpp"
#include <functional>
#include <string>
namespace targeted {
bool recover(ISource&, const Candidate&, const std::string&, std::string&,
             std::function<bool()> cancelled = std::function<bool()>());
}
