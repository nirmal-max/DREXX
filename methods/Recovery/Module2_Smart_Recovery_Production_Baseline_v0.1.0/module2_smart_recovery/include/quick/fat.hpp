#pragma once
#include "quick/filesystem.hpp"
#include <functional>
namespace quick {
class FatProvider {
public:
 static bool scan(ISource&, const FsContext&, std::vector<Candidate>&, std::vector<std::string>&, std::function<bool()>);
 static bool recover(ISource&, const Candidate&, const std::filesystem::path&, std::string&, std::function<bool()>);
};
}
