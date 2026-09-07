#pragma once
#include "quick/filesystem.hpp"
#include "quick/types.hpp"
#include <functional>
namespace quick {
class NtfsProvider {
public:
    static bool scan(ISource& src, const FsContext& fs, std::vector<Candidate>& out,
                     std::vector<std::string>& warnings, std::function<bool()> cancelled);
    static bool recover(ISource& src, const Candidate& c, const std::filesystem::path& dest,
                        std::string& error, std::function<bool()> cancelled);
};
}
