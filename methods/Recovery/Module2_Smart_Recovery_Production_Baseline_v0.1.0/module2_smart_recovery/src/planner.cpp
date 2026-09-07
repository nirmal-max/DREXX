#include "smart/planner.hpp"
#include <algorithm>
#include <cmath>
#include <numeric>

namespace smart {
static double clamp(double x,double a,double b){return std::max(a,std::min(b,x));}
std::string strategy_name(Strategy s){
 switch(s){case Strategy::Quick:return "quick";case Strategy::Filesystem:return "filesystem";case Strategy::Targeted:return "targeted";case Strategy::Deep:return "deep";case Strategy::DamagedMedia:return "damaged_media";case Strategy::ForensicReview:return "forensic_review";}return "unknown";
}
Plan make_plan(const quick::ScanResult& r){
 Plan p;
 double meta = r.candidates.empty()?0.0:clamp(double(r.candidates.size())/20.0,0.0,1.0);
 bool known=!r.partitions.empty();
 bool has_unknown=false; for(auto&w:r.warnings) if(w.find("unknown filesystem")!=std::string::npos) has_unknown=true;
 bool corrupt=r.status==quick::JobStatus::CorruptFilesystem;
 bool source_error=r.status==quick::JobStatus::SourceReadError;
 bool no_meta=r.status==quick::JobStatus::NoRecoverableMetadata;

 Score q{Strategy::Quick,0,{}};
 q.score=40+45*meta+(known?10:0)-(corrupt?35:0); q.reasons={"filesystem metadata-first strategy"}; if(!r.candidates.empty())q.reasons.push_back("recoverable deleted metadata candidates found");
 Score f{Strategy::Filesystem,20,{"filesystem reconstruction can exploit surviving structures"}};
 if(known)f.score+=20; if(corrupt)f.score+=25; if(has_unknown)f.score+=10;
 Score t{Strategy::Targeted,10,{"content-directed recovery is appropriate when metadata is incomplete"}};
 if(no_meta||has_unknown)t.score+=35; if(r.candidates.empty())t.score+=15;
 Score d{Strategy::Deep,15,{"broad logical reconstruction is appropriate when filesystem evidence is weak"}};
 if(corrupt)d.score+=45; if(no_meta)d.score+=20; if(has_unknown)d.score+=10;
 Score dm{Strategy::DamagedMedia,5,{"reserved for repeated source-read failures or media-health signals"}};
 if(source_error)dm.score+=60;
 Score fo{Strategy::ForensicReview,5,{"manual/provenance-heavy workflow when evidence preservation is required"}};
 p.ranking={q,f,t,d,dm,fo};
 std::sort(p.ranking.begin(),p.ranking.end(),[](const Score&a,const Score&b){return a.score>b.score;});
 p.selected=p.ranking.front().strategy;
 // Smart is deliberately conservative: if Quick has strong evidence, execute it. Otherwise return a handoff plan.
 p.execute_quick=(p.selected==Strategy::Quick && !r.candidates.empty() && r.status==quick::JobStatus::Success);
 p.rationale="Selected '"+strategy_name(p.selected)+"' because it has the highest evidence-weighted score ("+std::to_string(p.ranking.front().score)+").";
 if(source_error)p.warnings.push_back("Source read errors were observed; do not continue broad scanning until media/source handling is assessed.");
 if(no_meta)p.warnings.push_back("No recoverable filesystem metadata was found by Quick; Smart recommends escalation rather than pretending recovery is impossible.");
 if(corrupt)p.warnings.push_back("Filesystem evidence is degraded; Smart favors broader reconstruction.");
 return p;
}
Plan analyze_source(const std::string& source_path){ return make_plan(quick::run_quick_scan(source_path)); }
}
