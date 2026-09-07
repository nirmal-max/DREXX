#pragma once
#include <cstdint>
#include <string>
#include <vector>
namespace fsr {
enum class FsType { Unknown, NTFS, FAT12, FAT16, FAT32, exFAT, EXT2, EXT3, EXT4 };
enum class ObjectType { File, Directory, Unknown };
struct Extent { std::uint64_t logical{}, physical{}, length{}; };
struct FsObject {
 std::uint64_t id{}, parent{};
 ObjectType type{ObjectType::Unknown};
 std::string name;
 std::uint64_t size{};
 std::vector<Extent> extents;
 std::uint64_t mtime{}, ctime{}, atime{};
 bool deleted{};
};
struct Partition { std::uint32_t index{}; std::uint64_t offset{}, size{}; std::string type; };
struct Geometry {
 FsType type{FsType::Unknown}; std::uint32_t sector_size{}, cluster_size{};
 std::uint64_t volume_offset{}, volume_size{}, metadata_offset{};
};
struct Health { int score{}; std::vector<std::string> checks; std::vector<std::string> warnings; };
struct Result {
 std::string status{"invalid"};
 Geometry geometry;
 Health health;
 std::vector<FsObject> objects;
 std::vector<Partition> partitions;
 std::vector<std::string> warnings;
};
inline std::string fs_name(FsType x){switch(x){case FsType::NTFS:return"NTFS";case FsType::FAT12:return"FAT12";case FsType::FAT16:return"FAT16";case FsType::FAT32:return"FAT32";case FsType::exFAT:return"exFAT";case FsType::EXT2:return"EXT2";case FsType::EXT3:return"EXT3";case FsType::EXT4:return"EXT4";default:return"Unknown";}}
}
