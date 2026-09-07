#pragma once
#include <cstdint>
#include <string>
#include <vector>
namespace frag {
enum class FileType{PDF,JPEG,PNG,ZIP,Unknown};
enum class Confidence{Rejected,Weak,Probable,Strong};
struct Fragment{std::uint64_t id{},physical{},length{},file_offset{};FileType type{FileType::Unknown};double anchor_score{};std::vector<std::string> evidence;};
struct Edge{std::uint64_t from{},to{};double score{};std::vector<std::string> evidence;};
struct Chain{std::uint64_t id{};FileType type{FileType::Unknown};std::vector<std::uint64_t> fragments;std::uint64_t total_size{};double score{};Confidence confidence{Confidence::Rejected};std::vector<std::string> evidence;};
struct Result{std::string status{"invalid"};std::uint64_t source_size{},block_size{};std::vector<Fragment> fragments;std::vector<Edge> edges;std::vector<Chain> chains;};
inline std::string name(FileType t){switch(t){case FileType::PDF:return"pdf";case FileType::JPEG:return"jpeg";case FileType::PNG:return"png";case FileType::ZIP:return"zip";default:return"unknown";}}
}
