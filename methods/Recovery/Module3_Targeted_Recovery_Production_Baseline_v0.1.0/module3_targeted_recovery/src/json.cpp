#include "targeted/json.hpp"
#include <sstream>
namespace targeted {
static std::string q(const std::string&s){std::string o="\"";for(char c:s){if(c=='"'||c=='\\'){o+='\\';o+=c;}else if(c=='\n')o+="\\n";else o+=c;}return o+"\"";}
std::string to_json(const ScanResult&r){std::ostringstream o;o<<"{\"status\":"<<q(r.status)<<",\"source_size\":"<<r.source_size<<",\"bytes_scanned\":"<<r.bytes_scanned<<",\"candidates\":[";for(size_t i=0;i<r.candidates.size();i++){auto&c=r.candidates[i];if(i)o<<",";o<<"{\"id\":"<<c.id<<",\"rule\":"<<q(c.rule_id)<<",\"type\":"<<q(c.type)<<",\"name\":"<<q(c.name)<<",\"offset\":"<<c.offset<<",\"size\":"<<c.size<<",\"confidence\":"<<c.confidence<<",\"truncated\":"<<(c.truncated?"true":"false")<<",\"evidence\":[";for(size_t j=0;j<c.evidence.size();j++){if(j)o<<",";o<<q(c.evidence[j]);}o<<"]}";}o<<"],\"warnings\":[";for(size_t i=0;i<r.warnings.size();i++){if(i)o<<",";o<<q(r.warnings[i]);}o<<"]}"; return o.str(); }
}
