#pragma once
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace quick {

enum class FsType { Unknown, NTFS, FAT12, FAT16, FAT32, exFAT };
enum class JobStatus {
    Success, Partial, NoRecoverableMetadata, UnsupportedFilesystem,
    CorruptFilesystem, SourceReadError, Cancelled, InvalidInput
};

struct Extent {
    std::uint64_t logical_offset{};
    std::uint64_t physical_offset{};
    std::uint64_t length{};
};

struct Evidence {
    std::string code;
    std::string detail;
    int weight{};
};

struct Candidate {
    std::uint64_t id{};
    FsType filesystem{FsType::Unknown};
    std::uint64_t object_id{};
    std::string name;
    std::string path;
    std::uint64_t size{};
    bool deleted{};
    std::vector<Extent> extents;
    std::vector<Evidence> evidence;
    int confidence{};
};

struct SourceInfo {
    std::uint64_t size{};
    std::uint32_t sector_size{512};
    std::string identity;
};

struct Partition {
    std::uint32_t index{};
    std::uint64_t offset{};
    std::uint64_t size{};
    std::string type;
    std::string name;
};

struct ScanResult {
    JobStatus status{JobStatus::InvalidInput};
    SourceInfo source;
    std::vector<Partition> partitions;
    std::vector<Candidate> candidates;
    std::vector<std::string> warnings;
    std::uint64_t bytes_read{};
    std::string message;
};

inline std::string fs_name(FsType t) {
    switch (t) {
        case FsType::NTFS: return "NTFS";
        case FsType::FAT12: return "FAT12";
        case FsType::FAT16: return "FAT16";
        case FsType::FAT32: return "FAT32";
        case FsType::exFAT: return "exFAT";
        default: return "Unknown";
    }
}
inline std::string status_name(JobStatus s) {
    switch (s) {
        case JobStatus::Success: return "success";
        case JobStatus::Partial: return "partial";
        case JobStatus::NoRecoverableMetadata: return "no_recoverable_metadata";
        case JobStatus::UnsupportedFilesystem: return "unsupported_filesystem";
        case JobStatus::CorruptFilesystem: return "corrupt_filesystem";
        case JobStatus::SourceReadError: return "source_read_error";
        case JobStatus::Cancelled: return "cancelled";
        default: return "invalid_input";
    }
}

} // namespace quick
