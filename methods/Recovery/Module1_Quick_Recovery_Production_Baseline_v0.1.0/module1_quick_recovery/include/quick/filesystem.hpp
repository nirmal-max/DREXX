#pragma once
#include "quick/source.hpp"
#include "quick/types.hpp"
#include <memory>
namespace quick {
struct FsContext {
    FsType type{FsType::Unknown};
    std::uint64_t offset{};
    std::uint64_t size{};
    std::uint32_t sector_size{512};
};
FsContext detect_filesystem(ISource& src, const Partition& p);
}
