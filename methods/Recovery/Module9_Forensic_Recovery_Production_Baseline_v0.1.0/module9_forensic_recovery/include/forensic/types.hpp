#pragma once
#include <cstdint>
#include <string>
#include <vector>
namespace forensic {
struct Evidence{
 std::string id,path,kind,sha256;
 std::uint64_t size{};
 bool read_only{true};
};
struct Event{
 std::uint64_t sequence{};
 std::string timestamp_utc,type,actor,message,previous_hash,event_hash;
};
struct Case{
 std::string id,examiner,description,tool_version;
 std::vector<Evidence> evidence;
 std::vector<Event> events;
};
struct HashResult{bool ok{};std::string sha256;std::uint64_t size{};};
}
