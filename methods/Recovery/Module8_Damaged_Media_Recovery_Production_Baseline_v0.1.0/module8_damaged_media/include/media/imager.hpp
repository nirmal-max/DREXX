#pragma once
#include "media/source.hpp"
#include "media/types.hpp"
#include <functional>
#include <string>
namespace media {Result image(ISource&,const std::string&,const std::string&,Policy,std::function<bool()> = {});}
