#pragma once
#include <cstdint>
#include <string>
#include <vector>
namespace deep {
enum class FsType{Unknown,NTFS,FAT,exFAT,EXT};
struct Evidence{std::string kind;double weight{};std::string detail;};
struct Candidate{
 FsType type{FsType::Unknown}; std::uint64_t offset{},declared_size{},sector_size{},cluster_size{};
 double score{}; std::vector<Evidence> evidence; std::string status{"candidate"};
};
struct ScanRegion{std::uint64_t offset{},size{},stride{1024*1024};};
struct ScanState{std::uint64_t next_offset{},source_size{},region_offset{},region_size{},stride{};std::uint64_t candidates{};};
struct Result{std::string status{"invalid"};ScanRegion region;std::vector<Candidate> candidates;std::string state_file;};
inline std::string name(FsType t){switch(t){case FsType::NTFS:return"NTFS";case FsType::FAT:return"FAT";case FsType::exFAT:return"exFAT";case FsType::EXT:return"EXT";default:return"Unknown";}}
}
