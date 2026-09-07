#include "smart/report.hpp"
#include <sstream>
namespace smart {
static std::string esc(const std::string&s){std::string o;for(char c:s){if(c=='"'||c=='\\'){o+='\\';o+=c;}else if(c=='\n')o+="\\n";else o+=c;}return o;}
std::string plan_json(const Plan&p,const quick::ScanResult&r){std::ostringstream o;o<<"{\n  \"module\":\"smart\",\n  \"selected_strategy\":\""<<strategy_name(p.selected)<<"\",\n  \"execute_quick\":"<<(p.execute_quick?"true":"false")<<",\n  \"rationale\":\""<<esc(p.rationale)<<"\",\n  \"ranking\":[";for(size_t i=0;i<p.ranking.size();++i){if(i)o<<",";auto&s=p.ranking[i];o<<"{\"strategy\":\""<<strategy_name(s.strategy)<<"\",\"score\":"<<s.score<<",\"reasons\":[";for(size_t j=0;j<s.reasons.size();++j){if(j)o<<",";o<<"\""<<esc(s.reasons[j])<<"\"";}o<<"]}";}o<<"],\n  \"quick_status\":\""<<quick::status_name(r.status)<<"\",\n  \"candidate_count\":"<<r.candidates.size()<<",\n  \"warnings\":[";for(size_t i=0;i<p.warnings.size();++i){if(i)o<<",";o<<"\""<<esc(p.warnings[i])<<"\"";}o<<"]\n}\n";return o.str();}
}
