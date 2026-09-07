#pragma once
#include "raid/types.hpp"
#include "raid/source.hpp"
#include <memory>
#include <vector>
namespace raid {
Layout make_layout(Level,std::uint32_t,const std::vector<Member>&);
bool read_raid6(const Layout&,const std::vector<std::unique_ptr<ISource>>&,std::uint64_t,std::span<std::byte>);
bool read_raid10(const Layout&,const std::vector<std::unique_ptr<ISource>>&,std::uint64_t,std::span<std::byte>);
bool read_virtual(const Layout&,const std::vector<std::unique_ptr<ISource>>&,std::uint64_t,std::span<std::byte>);
bool export_virtual(const Layout&,const std::vector<std::unique_ptr<ISource>>&,std::uint64_t,std::uint64_t,const std::string&,std::string&);
}
