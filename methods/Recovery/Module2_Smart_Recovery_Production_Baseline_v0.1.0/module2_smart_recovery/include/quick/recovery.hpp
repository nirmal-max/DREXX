#pragma once
#include "quick/types.hpp"
#include <string>
#include <functional>
namespace quick {
ScanResult run_quick_scan(const std::string& source_path, std::function<bool()> cancelled = {});
bool recover_candidate(const std::string& source_path, const Candidate&, const std::string& destination, std::string& error, std::function<bool()> cancelled = {});
}
