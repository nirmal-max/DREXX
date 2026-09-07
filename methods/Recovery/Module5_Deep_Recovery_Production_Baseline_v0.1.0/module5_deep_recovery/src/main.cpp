#include "deep/source.hpp"
#include "deep/scanner.hpp"
#include "deep/json.hpp"
#include <fstream>
#include <iostream>
#include <cerrno>
#include <cstdlib>
#include <limits>
#include <string>

static void usage(){std::cout<<"deepscan --source image [--offset N --size N --stride N] [--state file] [--resume file] [--output file]\n";}

static bool parse_u64(const std::string& text, std::uint64_t& value){
    if(text.empty() || text[0]=='-') return false;
    errno=0; char* end=nullptr;
    const unsigned long long v=std::strtoull(text.c_str(),&end,10);
    if(errno==ERANGE || end==text.c_str() || *end!='\\0') return false;
    value=static_cast<std::uint64_t>(v);
    return true;
}

int main(int argc,char**argv){
    std::string src,out,state,resume;std::uint64_t off=0,size=0,stride=1024*1024;
    for(int i=1;i<argc;i++){
        std::string a=argv[i];
        if(a=="--source"&&i+1<argc)src=argv[++i];
        else if(a=="--output"&&i+1<argc)out=argv[++i];
        else if(a=="--offset"&&i+1<argc){if(!parse_u64(argv[++i],off)){std::cerr<<"invalid --offset\n";usage();return 2;}}
        else if(a=="--size"&&i+1<argc){if(!parse_u64(argv[++i],size)){std::cerr<<"invalid --size\n";usage();return 2;}}
        else if(a=="--stride"&&i+1<argc){if(!parse_u64(argv[++i],stride)||stride==0){std::cerr<<"invalid --stride\n";usage();return 2;}}
        else if(a=="--state"&&i+1<argc)state=argv[++i];
        else if(a=="--resume"&&i+1<argc)resume=argv[++i];
        else{std::cerr<<"usage: deepscan --source image [--offset N --size N --stride N] [--state file] [--resume file] [--output file]\n";return 2;}
    }
    if(src.empty()){std::cerr<<"--source required\n";return 2;}
    std::string e;auto s=deep::open_source(src,e);if(!s){std::cerr<<e<<"\n";return 3;}
    if(resume.empty()){
        if(off>s->size()){std::cerr<<"--offset exceeds source size\n";return 2;}
        if(size==0) size=s->size()-off;
        if(size>s->size()-off){std::cerr<<"--offset + --size exceeds source size\n";return 2;}
    }else{
        deep::ScanState st{};if(!deep::load_state(resume,st)){std::cerr<<"cannot load state\n";return 4;}
        if(st.region_offset>s->size() || st.region_size>s->size()-st.region_offset || st.stride==0){std::cerr<<"invalid resume state\n";return 4;}
        off=st.region_offset;size=st.region_size;stride=st.stride;
    }
    auto r=deep::scan(*s,{off,size,stride});
    if(!state.empty()){
        deep::ScanState st{};st.next_offset=off+size;st.source_size=s->size();st.region_offset=off;st.region_size=size;st.stride=stride;st.candidates=r.candidates.size();
        if(!deep::save_state(st,state)){std::cerr<<"cannot save state\n";return 5;}r.state_file=state;
    }
    auto j=deep::json(r);
    if(out.empty())std::cout<<j<<"\n";
    else{std::ofstream f(out,std::ios::binary|std::ios::trunc);if(!f){std::cerr<<"cannot write output\n";return 6;}f<<j;if(!f){std::cerr<<"cannot finalize output\n";return 6;}}
    return (r.status=="complete"||r.status=="no_filesystem_candidates")?0:1;
}
