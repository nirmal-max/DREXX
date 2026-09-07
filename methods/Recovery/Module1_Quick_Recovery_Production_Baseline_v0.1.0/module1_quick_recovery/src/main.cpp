#include "quick/recovery.hpp"
#include "quick/json.hpp"
#include <iostream>
#include <fstream>
#include <cstdlib>
#include <algorithm>
#include <cerrno>
#include <climits>
#include <stdexcept>

static void usage(){std::cout<<"quickscan --source <image|\\\\.\\PhysicalDriveN> [--output result.json] [--recover-candidate N --destination DIR]\n";}

static bool parse_candidate_id(const std::string& text, long long& value) {
    if (text.empty()) return false;
    errno = 0;
    char* end = nullptr;
    const long long parsed = std::strtoll(text.c_str(), &end, 10);
    if (errno == ERANGE || end == text.c_str() || *end != '\0') return false;
    value = parsed;
    return true;
}

int main(int argc,char**argv){
    std::string source,outfile;long long recover=-1;std::string dest;
    for(int i=1;i<argc;i++){
        std::string a=argv[i];
        if(a=="--source"&&i+1<argc) source=argv[++i];
        else if(a=="--output"&&i+1<argc) outfile=argv[++i];
        else if(a=="--recover-candidate"&&i+1<argc){
            if(!parse_candidate_id(argv[++i], recover) || recover < 0){
                std::cerr<<"invalid --recover-candidate value\n";usage();return 2;
            }
        }
        else if(a=="--destination"&&i+1<argc) dest=argv[++i];
        else if(a=="--help"){usage();return 0;}
        else{std::cerr<<"unknown argument: "<<a<<"\n";usage();return 2;}
    }
    if(source.empty()){usage();return 2;}
    auto r=quick::run_quick_scan(source);
    if(!outfile.empty()){
        std::ofstream f(outfile);
        if(!f){std::cerr<<"cannot write output\n";return 3;}
        f<<quick::result_json(r);
        if(!f){std::cerr<<"cannot finalize output\n";return 3;}
    }else std::cout<<quick::result_json(r);
    if(recover>=0){
        auto it=std::find_if(r.candidates.begin(),r.candidates.end(),[&](const auto&c){return static_cast<long long>(c.id)==recover;});
        if(it==r.candidates.end()){std::cerr<<"candidate not found\n";return 4;}
        if(dest.empty()){std::cerr<<"--destination is required for recovery\n";return 4;}
        std::string e;
        if(!quick::recover_candidate(source,*it,dest,e)){std::cerr<<"recovery failed: "<<e<<"\n";return 5;}
    }
    return 0;
}
