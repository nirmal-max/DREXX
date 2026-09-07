#include "smart/planner.hpp"
#include <cassert>
#include <iostream>
int main(){
 quick::ScanResult r{}; r.status=quick::JobStatus::Success; r.partitions.push_back({1,0,100000,"NTFS",{}}); quick::Candidate c{}; c.id=1; c.filesystem=quick::FsType::NTFS; c.deleted=true; r.candidates.push_back(c); auto p=smart::make_plan(r); assert(p.selected==smart::Strategy::Quick); assert(p.execute_quick);
 quick::ScanResult n{}; n.status=quick::JobStatus::NoRecoverableMetadata; n.partitions.push_back({1,0,100000,"WHOLE_SOURCE",{}}); auto p2=smart::make_plan(n); assert(p2.selected==smart::Strategy::Targeted || p2.selected==smart::Strategy::Deep);
 quick::ScanResult e{}; e.status=quick::JobStatus::SourceReadError; auto p3=smart::make_plan(e); assert(p3.selected==smart::Strategy::DamagedMedia); std::cout<<"all smart tests passed\n";
}
