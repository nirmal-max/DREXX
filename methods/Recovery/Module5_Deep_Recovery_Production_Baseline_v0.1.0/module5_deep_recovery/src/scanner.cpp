#include "deep/scanner.hpp"
#include "deep/types.hpp"
#include <algorithm>
#include <cmath>
#include <fstream>
namespace deep{
std::vector<Candidate> detect_at(ISource&,std::uint64_t);
static bool near(const Candidate&a,const Candidate&b){auto d=a.offset>b.offset?a.offset-b.offset:b.offset-a.offset;return a.type==b.type&&d<1024*1024;}
Result scan(ISource&s,ScanRegion r,std::function<bool()>cancelled){
 Result out{};out.region=r;if(r.size==0||r.offset>=s.size()){out.status="invalid_region";return out;}r.size=std::min(r.size,s.size()-r.offset);r.stride=std::max<std::uint64_t>(512,r.stride);
 std::vector<Candidate> raw;
 // Coarse pass. A second refinement pass is triggered around every anchor.
 for(std::uint64_t p=r.offset;p<r.offset+r.size;){
  if(cancelled&&cancelled()){out.status="cancelled";break;}
  auto x=detect_at(s,p);raw.insert(raw.end(),x.begin(),x.end());
  if(r.stride>512 && !x.empty()){auto start=p>r.stride?p-r.stride:p;auto end=std::min(r.offset+r.size,p+r.stride);for(std::uint64_t q=start;q<end;q+=512){if(cancelled&&cancelled()){out.status="cancelled";break;}auto y=detect_at(s,q);raw.insert(raw.end(),y.begin(),y.end());}}
  if(p>r.offset+r.size-r.stride)break;p+=r.stride;
 }
 // Cluster nearby hypotheses and retain the strongest evidence set.
 std::sort(raw.begin(),raw.end(),[](const auto&a,const auto&b){return a.score>b.score;});
 for(auto&c:raw){bool merged=false;for(auto&k:out.candidates)if(near(c,k)){if(c.score>k.score)k=c;merged=true;break;}if(!merged)out.candidates.push_back(c);}
 std::sort(out.candidates.begin(),out.candidates.end(),[](const auto&a,const auto&b){return a.score>b.score;});
 if(out.status=="invalid")out.status=out.candidates.empty()?"no_filesystem_candidates":"complete";
 return out;
}
}
