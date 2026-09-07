#include "smart/planner.hpp"
#include "smart/report.hpp"
#include "quick/recovery.hpp"
#include "quick/json.hpp"
#include <fstream>
#include <iostream>
#include <string>

static void usage(){
    std::cout<<"smartscan --source <image|\\\\.\\PhysicalDriveN> [--output plan.json] [--auto-quick]\n";
}

int main(int argc,char**argv){
    std::string source,out;
    bool auto_quick=false;
    for(int i=1;i<argc;i++){
        std::string a=argv[i];
        if(a=="--source"&&i+1<argc) source=argv[++i];
        else if(a=="--output"&&i+1<argc) out=argv[++i];
        else if(a=="--auto-quick") auto_quick=true;
        else if(a=="--help"){usage();return 0;}
        else{usage();return 2;}
    }
    if(source.empty()){usage();return 2;}

    auto r=quick::run_quick_scan(source);
    auto p=smart::make_plan(r);

    const auto report = smart::plan_json(p,r);
    if(!out.empty()){
        std::ofstream f(out);
        if(!f){std::cerr<<"cannot write output\n";return 3;}
        f<<report;
        if(!f){std::cerr<<"cannot finalize output\n";return 3;}
    }

    // --auto-quick is planning-only: it must not silently execute recovery.
    // Emit the plan to stdout when no output file was requested, including in auto mode.
    if(out.empty()) std::cout<<report;

    return r.status==quick::JobStatus::SourceReadError?5:0;
}
