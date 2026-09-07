#pragma once
#include "quick/recovery.hpp"
#include "quick/types.hpp"
#include <string>
#include <vector>

namespace smart {

enum class Strategy { Quick, Filesystem, Targeted, Deep, DamagedMedia, ForensicReview };
struct Score {
    Strategy strategy{};
    double score{};
    std::vector<std::string> reasons;
};
struct Plan {
    Strategy selected{Strategy::Quick};
    std::vector<Score> ranking;
    std::vector<std::string> warnings;
    bool execute_quick{false};
    std::string rationale;
};

std::string strategy_name(Strategy);
Plan make_plan(const quick::ScanResult& quick_result);
Plan analyze_source(const std::string& source_path);

}
