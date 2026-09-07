#pragma once
#include <cstdint>
#include <string>
#include <vector>
namespace media {
enum class State{Unknown,Good,Failed};
struct Sector{State state{State::Unknown};std::uint32_t attempts{};std::uint64_t last_error{};};
struct Map{std::uint64_t sector_size{512},sector_count{};std::vector<Sector> sectors;};
struct Policy{std::uint32_t block_sectors{256},retries{2},split_min_sectors{1};bool reverse_pass{true};std::uint8_t fill{0};};
struct Stats{std::uint64_t good{},failed{},attempts{},bytes_read{};};
struct Result{std::string status{"invalid"};Stats stats;Map map;std::string image,map_path;};
}
