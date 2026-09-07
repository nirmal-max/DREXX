#pragma once
#include "quick/types.hpp"
#include <cstddef>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace quick {

class ISource {
public:
    virtual ~ISource() = default;
    virtual bool read_at(std::uint64_t offset, std::span<std::byte> out) = 0;
    virtual std::uint64_t size() const = 0;
    virtual std::string identity() const = 0;
};

std::unique_ptr<ISource> open_source(const std::string& path, std::string& error);

bool read_exact(ISource& src, std::uint64_t offset, std::vector<std::byte>& out);

} // namespace quick
