#include "media/source.hpp"
#include "media/imager.hpp"
#include "media/strategy.hpp"
#include "media/json.hpp"
#include <cerrno>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>

static bool parse_u32(const std::string& text, std::uint32_t& value){
    if(text.empty() || text[0]=='-') return false;
    errno=0; char* end=nullptr;
    unsigned long long v=std::strtoull(text.c_str(),&end,10);
    if(errno==ERANGE || end==text.c_str() || *end!='\0' || v>0xffffffffULL) return false;
    value=static_cast<std::uint32_t>(v);
    return true;
}

int main(int argc,char**argv){
    std::string src,dst,map,out; auto p=media::production_policy();
    for(int i=1;i<argc;i++){
        std::string a=argv[i];
        if(a=="--source"&&i+1<argc) src=argv[++i];
        else if(a=="--output"&&i+1<argc) dst=argv[++i];
        else if(a=="--map"&&i+1<argc) map=argv[++i];
        else if(a=="--report"&&i+1<argc) out=argv[++i];
        else if(a=="--block-sectors"&&i+1<argc){if(!parse_u32(argv[++i],p.block_sectors)||p.block_sectors==0){std::cerr<<"invalid --block-sectors\n";return 2;}}
        else if(a=="--retries"&&i+1<argc){if(!parse_u32(argv[++i],p.retries)){std::cerr<<"invalid --retries\n";return 2;}}
        else {std::cerr<<"usage: mediaimager --source input --output image --map map [--block-sectors N --retries N --report json]\n";return 2;}
    }
    if(src.empty()||dst.empty()||map.empty()){std::cerr<<"source/output/map required\n";return 2;}
    if(src==dst){std::cerr<<"refusing source==destination\n";return 3;}
    std::string e; auto s=media::open_source(src,e); if(!s){std::cerr<<e<<"\n";return 3;}
    auto r=media::image(*s,dst,map,p); auto j=media::json(r);
    if(out.empty()) std::cout<<j<<"\n";
    else {std::ofstream f(out,std::ios::binary|std::ios::trunc); if(!f){std::cerr<<"cannot write report\n";return 5;} f<<j; if(!f){std::cerr<<"cannot finalize report\n";return 5;}}
    return r.status=="complete"?0:1;
}
