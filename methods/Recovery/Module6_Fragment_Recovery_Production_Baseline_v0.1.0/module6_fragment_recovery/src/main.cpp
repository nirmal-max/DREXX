#include "fragment/source.hpp"
#include "fragment/signatures.hpp"
#include "fragment/chains.hpp"
#include "fragment/reconstruct.hpp"
#include "fragment/json.hpp"
#include <fstream>
#include <iostream>
#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <limits>
#include <string>

static void usage(){std::cout<<"usage: fragmentscan --source image --type pdf|jpeg|png|zip [--block-size N] [--limit N] [--output file] [--recover ID --destination dir]\n";}
static bool parse_u64(const std::string& s,std::uint64_t& v){if(s.empty()||s[0]=='-')return false;errno=0;char*end=nullptr;auto x=std::strtoull(s.c_str(),&end,10);if(errno==ERANGE||end==s.c_str()||*end!='\\0')return false;v=(std::uint64_t)x;return true;}
static bool parse_i64(const std::string& s,long long& v){if(s.empty())return false;errno=0;char*end=nullptr;auto x=std::strtoll(s.c_str(),&end,10);if(errno==ERANGE||end==s.c_str()||*end!='\\0')return false;v=x;return true;}
int main(int argc,char**argv){
    std::string src,type_s,out,dest;std::uint64_t block=4096,limit=0;long long recover=-1;
    for(int i=1;i<argc;i++){std::string a=argv[i];
        if(a=="--source"&&i+1<argc)src=argv[++i];
        else if(a=="--type"&&i+1<argc)type_s=argv[++i];
        else if(a=="--block-size"&&i+1<argc){if(!parse_u64(argv[++i],block)||block==0){std::cerr<<"invalid --block-size\n";usage();return 2;}}
        else if(a=="--limit"&&i+1<argc){if(!parse_u64(argv[++i],limit)){std::cerr<<"invalid --limit\n";usage();return 2;}}
        else if(a=="--output"&&i+1<argc)out=argv[++i];
        else if(a=="--recover"&&i+1<argc){if(!parse_i64(argv[++i],recover)||recover<0){std::cerr<<"invalid --recover\n";usage();return 2;}}
        else if(a=="--destination"&&i+1<argc)dest=argv[++i];
        else{usage();return 2;}
    }
    if(src.empty()||type_s.empty()){std::cerr<<"source and type required\n";return 2;}
    std::string e;auto s=frag::open_source(src,e);if(!s){std::cerr<<e<<"\n";return 3;}
    auto t=frag::parse_type(type_s);if(t==frag::FileType::Unknown){std::cerr<<"unsupported type\n";return 3;}
    if(!limit)limit=s->size();if(limit>s->size()){std::cerr<<"--limit exceeds source size\n";return 2;}
    auto fs=frag::find_anchors(*s,t,block,limit);auto es=frag::build_edges(*s,fs,block);auto cs=frag::build_chains(fs,es,8);
    frag::Result r{};r.status=cs.empty()?"no_chains":"complete";r.source_size=s->size();r.block_size=block;r.fragments=fs;r.edges=es;r.chains=cs;
    auto j=frag::json(r);if(out.empty())std::cout<<j<<"\n";else{std::ofstream f(out,std::ios::binary|std::ios::trunc);if(!f){std::cerr<<"cannot write output\n";return 6;}f<<j;if(!f){std::cerr<<"cannot finalize output\n";return 6;}}
    if(recover>=0){auto it=std::find_if(cs.begin(),cs.end(),[&](const auto&c){return(long long)c.id==recover;});if(it==cs.end()){std::cerr<<"chain not found\n";return 4;}if(dest.empty()){std::cerr<<"destination required\n";return 4;}if(!frag::recover(*s,*it,fs,dest,e)){std::cerr<<e<<"\n";return 5;}}
    return 0;
}
