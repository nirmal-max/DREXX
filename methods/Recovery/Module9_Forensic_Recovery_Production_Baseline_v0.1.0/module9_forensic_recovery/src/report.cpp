#include "forensic/report.hpp"
#include "forensic/sha256.hpp"
#include <fstream>
#include <sstream>
namespace forensic {
static std::string q(const std::string&s){std::string o="\"";for(char c:s){if(c=='"'||c=='\\'){o+='\\';o+=c;}else if(c=='\n')o+="\\n";else o+=c;}return o+"\"";}
std::string json(const Case&c){std::ostringstream o;o<<"{\"case_id\":"<<q(c.id)<<",\"examiner\":"<<q(c.examiner)<<",\"description\":"<<q(c.description)<<",\"tool_version\":"<<q(c.tool_version)<<",\"evidence\":[";for(size_t i=0;i<c.evidence.size();i++){auto&e=c.evidence[i];if(i)o<<",";o<<"{\"id\":"<<q(e.id)<<",\"path\":"<<q(e.path)<<",\"kind\":"<<q(e.kind)<<",\"sha256\":"<<q(e.sha256)<<",\"size\":"<<e.size<<",\"read_only\":"<<(e.read_only?"true":"false")<<"}";}o<<"],\"events\":[";for(size_t i=0;i<c.events.size();i++){auto&e=c.events[i];if(i)o<<",";o<<"{\"sequence\":"<<e.sequence<<",\"timestamp\":"<<q(e.timestamp_utc)<<",\"type\":"<<q(e.type)<<",\"actor\":"<<q(e.actor)<<",\"message\":"<<q(e.message)<<",\"previous_hash\":"<<q(e.previous_hash)<<",\"event_hash\":"<<q(e.event_hash)<<"}";}o<<"]}";return o.str();}
bool write_report(const Case&c,const std::string&p){std::ofstream f(p,std::ios::trunc);if(!f)return false;f<<json(c);return bool(f);}
}
