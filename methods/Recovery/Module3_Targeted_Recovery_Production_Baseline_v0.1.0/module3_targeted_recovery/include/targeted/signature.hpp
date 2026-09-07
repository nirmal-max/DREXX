#pragma once
#include "targeted/types.hpp"
#include <string>
#include <vector>
namespace targeted {
std::vector<Rule> built_in_rules();
std::vector<Rule> load_rules_json(const std::string&path,std::string&error);
std::vector<std::string> list_rule_ids();
}
