#include "media/json.hpp"
#include <sstream>
namespace media{static std::string q(const std::string&s){std::string o="\"";for(char c:s){if(c=='"'||c=='\\'){o+='\\';o+=c;}else o+=c;}return o+"\"";}std::string json(const Result&r){std::ostringstream o;o<<"{\"status\":"<<q(r.status)<<",\"image\":"<<q(r.image)<<",\"map\":"<<q(r.map_path)<<",\"sector_size\":"<<r.map.sector_size<<",\"sector_count\":"<<r.map.sector_count<<",\"good\":"<<r.stats.good<<",\"failed\":"<<r.stats.failed<<",\"attempts\":"<<r.stats.attempts<<",\"bytes_read\":"<<r.stats.bytes_read<<"}";return o.str();}}
