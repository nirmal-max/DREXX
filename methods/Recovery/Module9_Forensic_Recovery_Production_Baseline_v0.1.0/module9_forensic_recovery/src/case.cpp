#include "forensic/case.hpp"
#include "forensic/sha256.hpp"
#include <fstream>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <cstdio>
namespace forensic {
static std::string q(const std::string&s){std::string o="\"";for(char c:s){if(c=='"'||c=='\\'){o+='\\';o+=c;}else if(c=='\n')o+="\\n";else o+=c;}return o+"\"";}
static std::string now(){auto t=std::time(nullptr);std::tm u{};
#ifdef _WIN32
 gmtime_s(&u,&t);
#else
 gmtime_r(&t,&u);
#endif
 std::ostringstream o;o<<std::put_time(&u,"%Y-%m-%dT%H:%M:%SZ");return o.str();}
static std::string event_canon(const Event&e){return std::to_string(e.sequence)+"|"+e.timestamp_utc+"|"+e.type+"|"+e.actor+"|"+e.message+"|"+e.previous_hash;}
bool save_case(const Case&c,const std::string&p){auto tmp=p+".tmp";std::ofstream f(tmp,std::ios::trunc);if(!f)return false;f<<"FORENSIC_CASE_V1\n"<<c.id<<"\n"<<c.examiner<<"\n"<<c.description<<"\n"<<c.tool_version<<"\n";f<<"EVIDENCE "<<c.evidence.size()<<"\n";for(auto&e:c.evidence)f<<e.id<<"\t"<<e.path<<"\t"<<e.kind<<"\t"<<e.sha256<<"\t"<<e.size<<"\t"<<e.read_only<<"\n";f<<"EVENTS "<<c.events.size()<<"\n";for(auto&e:c.events)f<<e.sequence<<"\t"<<e.timestamp_utc<<"\t"<<e.type<<"\t"<<e.actor<<"\t"<<e.message<<"\t"<<e.previous_hash<<"\t"<<e.event_hash<<"\n";f.close();std::remove(p.c_str());return std::rename(tmp.c_str(),p.c_str())==0;}
bool load_case(const std::string&p,Case&c){std::ifstream f(p);std::string h;if(!std::getline(f,h)||h!="FORENSIC_CASE_V1")return false;std::getline(f,c.id);std::getline(f,c.examiner);std::getline(f,c.description);std::getline(f,c.tool_version);std::string tag;size_t n;if(!(f>>tag>>n)||tag!="EVIDENCE")return false;std::string x;std::getline(f,x);for(size_t i=0;i<n;i++){Evidence e;std::getline(f,x);std::stringstream s(x);std::getline(s,e.id,'\t');std::getline(s,e.path,'\t');std::getline(s,e.kind,'\t');std::getline(s,e.sha256,'\t');s>>e.size>>e.read_only;c.evidence.push_back(e);}if(!(f>>tag>>n)||tag!="EVENTS")return false;std::getline(f,x);for(size_t i=0;i<n;i++){Event e;std::getline(f,x);std::stringstream s(x);std::string z;std::getline(s,z,'\t');e.sequence=std::stoull(z);std::getline(s,e.timestamp_utc,'\t');std::getline(s,e.type,'\t');std::getline(s,e.actor,'\t');std::getline(s,e.message,'\t');std::getline(s,e.previous_hash,'\t');std::getline(s,e.event_hash);c.events.push_back(e);}return true;}
bool init_case(const std::string&id,const std::string&ex,const std::string&desc,Case&c,std::string&e){c={};c.id=id;c.examiner=ex;c.description=desc;c.tool_version="Module9-0.1.0";if(!append_event(c,"case_opened",ex,"Case initialized")){e="cannot initialize event chain";return false;}return true;}
bool append_event(Case&c,const std::string&type,const std::string&actor,const std::string&msg){Event e{};e.sequence=c.events.size();e.timestamp_utc=now();e.type=type;e.actor=actor;e.message=msg;e.previous_hash=c.events.empty()?"":c.events.back().event_hash;std::uint64_t dummy=0;std::string tmp="/tmp/forensic_event.tmp";{std::ofstream f(tmp,std::ios::trunc);f<<event_canon(e);}std::string er;e.event_hash=sha256_file(tmp,dummy,er);std::remove(tmp.c_str());if(e.event_hash.empty())return false;c.events.push_back(e);return true;}
}
