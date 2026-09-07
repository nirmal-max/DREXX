#pragma once
#include "fsrecover/types.hpp"
#include "fsrecover/source.hpp"
#include <functional>
namespace fsr {
bool scan_ntfs(ISource&,const Geometry&,std::vector<FsObject>&,Health&,std::function<bool()> cancelled = std::function<bool()>());
bool scan_fat(ISource&,const Geometry&,std::vector<FsObject>&,Health&,std::function<bool()> cancelled = std::function<bool()>());
bool scan_exfat(ISource&,const Geometry&,std::vector<FsObject>&,Health&,std::function<bool()> cancelled = std::function<bool()>());
bool scan_ext(ISource&,const Geometry&,std::vector<FsObject>&,Health&,std::function<bool()> cancelled = std::function<bool()>());
}
