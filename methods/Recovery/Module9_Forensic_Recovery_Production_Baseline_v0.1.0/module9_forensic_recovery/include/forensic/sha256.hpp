#pragma once
#include <cstdint>
#include <span>
#include <string>
namespace forensic {
class Sha256 {
 std::uint32_t h[8]; std::uint64_t bits{}; std::uint8_t buf[64]{}; std::size_t used{};
 void transform(const std::uint8_t*);
 public:
 Sha256();
 void update(std::span<const std::byte>);
 std::string final();
};
std::string sha256_file(const std::string&,std::uint64_t&,std::string&);
}
