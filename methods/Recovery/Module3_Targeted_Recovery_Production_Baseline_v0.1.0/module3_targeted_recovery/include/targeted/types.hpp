#pragma once
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>
#include <optional>
#include <functional>
namespace targeted {
enum class MatchKind { StartOnly, StartEnd, FixedSize, Validated };
struct Signature { std::vector<std::uint8_t> bytes; std::vector<std::uint8_t> mask; std::int64_t offset_min{0}, offset_max{0}; };
struct Rule {
 std::string id, name, extension, group;
 Signature start;
 std::optional<Signature> end;
 std::uint64_t fixed_size{0};
 std::uint64_t max_size{64ULL*1024*1024};
 bool contiguous_only{true};
};
struct Extent { std::uint64_t physical{}, length{}; };
struct Candidate {
 std::uint64_t id{};
 std::string rule_id, type, extension, name;
 std::uint64_t offset{}, size{};
 MatchKind kind{MatchKind::StartOnly};
 std::vector<Extent> extents;
 std::vector<std::string> evidence;
 int confidence{};
 bool truncated{};
};
struct ScanResult {
 std::string status{"success"};
 std::uint64_t source_size{}, bytes_scanned{};
 std::vector<Candidate> candidates;
 std::vector<std::string> warnings;
};
}
