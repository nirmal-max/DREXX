#include "targeted/source.hpp"
#include "targeted/signature.hpp"
#include "targeted/scanner.hpp"
#include "targeted/validator.hpp"
#include "targeted/recovery.hpp"
#include "targeted/json.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <limits>
static void usage(){std::cout<<"targetedscan --source <image> [--types pdf,jpeg] [--rules file] [--output result.json] [--recover N --destination dir]\n";}
static bool parse_id(const std::string&s,long long&v){if(s.empty())return false;errno=0;char*end=nullptr;const long long x=std::strtoll(s.c_str(),&end,10);if(errno==ERANGE||end==s.c_str()||*end!='\0'||x<0)return false;v=x;return true;}
int main(int argc,char**argv){
 std::string source,types,outfile,rulesfile,dest;long long recover_id=-1;
 for(int i=1;i<argc;i++){std::string a=argv[i];if(a=="--source"&&i+1<argc)source=argv[++i];else if(a=="--types"&&i+1<argc)types=argv[++i];else if(a=="--rules"&&i+1<argc)rulesfile=argv[++i];else if(a=="--output"&&i+1<argc)outfile=argv[++i];else if(a=="--recover"&&i+1<argc){if(!parse_id(argv[++i],recover_id)){std::cerr<<"invalid --recover value\n";usage();return 2;}}else if(a=="--destination"&&i+1<argc)dest=argv[++i];else if(a=="--list-rules"){for(auto&s:targeted::list_rule_ids())std::cout<<s<<"\n";return 0;}else {usage();return 2;}}
 if(source.empty()){usage();return 2;}
 auto rules=targeted::built_in_rules();if(!rulesfile.empty()){std::string e;auto x=targeted::load_rules_json(rulesfile,e);if(e.empty())rules.insert(rules.end(),x.begin(),x.end());else{std::cerr<<e<<"\n";return 3;}}
 if(!types.empty()){std::vector<std::string>want;std::stringstream ss(types);std::string x;while(std::getline(ss,x,','))want.push_back(x);rules.erase(std::remove_if(rules.begin(),rules.end(),[&](auto&r){return std::find(want.begin(),want.end(),r.id)==want.end();}),rules.end());}
 std::string e;auto src=targeted::open_source(source,e);if(!src){std::cerr<<e<<"\n";return 4;}
 auto result=targeted::scan(*src,rules);for(auto&c:result.candidates)targeted::validate_candidate(*src,c);
 if(!outfile.empty()){std::ofstream f(outfile);if(!f){std::cerr<<"cannot open output\n";return 3;}f<<targeted::to_json(result);if(!f){std::cerr<<"cannot finalize output\n";return 3;}}else std::cout<<targeted::to_json(result)<<"\n";
 if(recover_id>=0){auto it=std::find_if(result.candidates.begin(),result.candidates.end(),[&](auto&c){return static_cast<long long>(c.id)==recover_id;});if(it==result.candidates.end()){std::cerr<<"candidate not found\n";return 5;}if(dest.empty()){std::cerr<<"destination required\n";return 5;}if(!targeted::recover(*src,*it,dest,e)){std::cerr<<e<<"\n";return 6;}}
 return 0;
}
