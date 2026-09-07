#include "forensic/case.hpp"
#include "forensic/acquire.hpp"
#include "forensic/report.hpp"
#include <fstream>
#include <iostream>

static bool save_checked(const forensic::Case& c, const std::string& path) {
    if (!forensic::save_case(c, path)) { std::cerr << "cannot save case\n"; return false; }
    return true;
}

int main(int argc,char**argv){
    if(argc<2){std::cerr<<"commands: init|acquire|hash|verify|event|report\n";return 2;}
    std::string cmd=argv[1],casefile,id,actor,desc,src,dst,type,msg,out,file;
    for(int i=2;i<argc;i++){
        std::string a=argv[i];
        if(a=="--case"&&i+1<argc)casefile=argv[++i];
        else if(a=="--id"&&i+1<argc)id=argv[++i];
        else if(a=="--examiner"&&i+1<argc)actor=argv[++i];
        else if(a=="--description"&&i+1<argc)desc=argv[++i];
        else if(a=="--source"&&i+1<argc)src=argv[++i];
        else if(a=="--evidence"&&i+1<argc)dst=argv[++i];
        else if(a=="--type"&&i+1<argc)type=argv[++i];
        else if(a=="--message"&&i+1<argc)msg=argv[++i];
        else if(a=="--file"&&i+1<argc)file=argv[++i];
        else if(a=="--output"&&i+1<argc)out=argv[++i];
        else{std::cerr<<"unknown argument\n";return 2;}
    }
    if(cmd=="init"){
        if(casefile.empty()||id.empty()||actor.empty()){std::cerr<<"--case --id --examiner required\n";return 2;}
        forensic::Case c;std::string e;
        if(!forensic::init_case(id,actor,desc,c,e)||!save_checked(c,casefile)){std::cerr<<(e.empty()?"cannot initialize case":e)<<"\n";return 3;}
        return 0;
    }
    if(casefile.empty()){std::cerr<<"--case required\n";return 2;}
    forensic::Case c;if(!forensic::load_case(casefile,c)){std::cerr<<"cannot load case\n";return 3;}
    if(cmd=="hash"||cmd=="verify"){
        if(file.empty()){std::cerr<<"--file required\n";return 2;}
        auto h=forensic::hash_file(file);if(!h.ok){std::cerr<<"cannot hash file\n";return 4;}
        std::cout<<h.sha256<<" "<<h.size<<"\n";
        if(cmd=="verify"){
            for(auto&e:c.evidence)if(e.path==file){std::cout<<(e.sha256==h.sha256?"MATCH":"MISMATCH")<<"\n";return e.sha256==h.sha256?0:5;}
            std::cerr<<"file not registered\n";return 5;
        }
        return 0;
    }
    if(cmd=="acquire"){
        if(src.empty()||dst.empty()){std::cerr<<"--source --evidence required\n";return 2;}
        std::uint64_t n;std::string e;
        if(!forensic::acquire_file(src,dst,n,e)){std::cerr<<e<<"\n";return 4;}
        auto h=forensic::hash_file(dst);
        if(!h.ok||h.size!=n){std::cerr<<"acquired evidence verification failed\n";return 4;}
        forensic::Evidence ev{};ev.id="EV-"+std::to_string(c.evidence.size()+1);ev.path=dst;ev.kind="acquired_image";ev.sha256=h.sha256;ev.size=h.size;ev.read_only=true;
        c.evidence.push_back(ev);forensic::append_event(c,"acquisition",c.examiner,"Acquired evidence copy "+ev.id);
        if(!save_checked(c,casefile))return 5;
        std::cout<<ev.id<<" "<<ev.sha256<<"\n";return 0;
    }
    if(cmd=="event"){
        if(type.empty()||actor.empty()||msg.empty()){std::cerr<<"--type --examiner --message required\n";return 2;}
        if(!forensic::append_event(c,type,actor,msg)||!save_checked(c,casefile))return 5;return 0;
    }
    if(cmd=="report"){
        if(out.empty())out=casefile+".json";
        if(!forensic::write_report(c,out)){std::cerr<<"cannot write report\n";return 5;}return 0;
    }
    std::cerr<<"unknown command\n";return 2;
}
