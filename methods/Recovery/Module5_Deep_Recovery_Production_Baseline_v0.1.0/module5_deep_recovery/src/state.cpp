#include "deep/scanner.hpp"
#include <fstream>
namespace deep{
bool save_state(const ScanState&s,const std::string&p){std::ofstream f(p,std::ios::trunc);if(!f)return false;f<<s.next_offset<<"\n"<<s.source_size<<"\n"<<s.region_offset<<"\n"<<s.region_size<<"\n"<<s.stride<<"\n"<<s.candidates<<"\n";return true;}
bool load_state(const std::string&p,ScanState&s){std::ifstream f(p);if(!f)return false;return bool(f>>s.next_offset>>s.source_size>>s.region_offset>>s.region_size>>s.stride>>s.candidates);}
}
