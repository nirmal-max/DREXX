#pragma once
#include "targeted/types.hpp"
#include "targeted/source.hpp"
#include <functional>
namespace targeted {
bool validate_candidate(ISource&, Candidate&, std::function<bool()> cancelled = {});
}
