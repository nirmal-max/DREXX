#pragma once
#include <cstdint>
#include <string>
#include <vector>
namespace raid {
enum class Level{Linear,R0,R1,R5,R6,R10};
struct Member{std::uint32_t index{};std::string path;std::uint64_t size{};bool missing{};};
struct Layout{Level level{Level::Linear};std::uint32_t stripe_sectors{128};std::uint32_t chunk_disks{0};std::vector<std::uint32_t> order;std::uint64_t logical_size{};double score{};std::vector<std::string> evidence;};
struct Result{std::string status{"invalid"};Layout layout;std::vector<Member> members;std::vector<std::string> warnings;};
inline std::string name(Level l){switch(l){case Level::Linear:return"linear";case Level::R0:return"raid0";case Level::R1:return"raid1";case Level::R5:return"raid5";case Level::R6:return"raid6";case Level::R10:return"raid10";}return"unknown";}
}
