#pragma once
#include "fsrecover/source.hpp"
#include "fsrecover/types.hpp"
#include <functional>
namespace fsr { Result reconstruct(ISource&,std::function<bool()> cancelled = std::function<bool()>()); }
