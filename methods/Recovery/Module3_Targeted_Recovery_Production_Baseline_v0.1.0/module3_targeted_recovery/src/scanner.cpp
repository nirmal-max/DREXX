#include "targeted/scanner.hpp"
#include <algorithm>
#include <cstring>
#include <tuple>
namespace targeted {
static bool match(const std::byte*p,const Signature&s){
 if(s.bytes.empty()||s.bytes.size()!=s.mask.size())return false;
 for(size_t i=0;i<s.bytes.size();i++)if((std::to_integer<unsigned char>(p[i])&s.mask[i])!=(s.bytes[i]&s.mask[i]))return false;
 return true;
}
static std::uint64_t next_end(ISource&src,const Rule&r,std::uint64_t from,std::uint64_t max){
 if(!r.end)return 0;
 std::vector<std::byte>b(1024*1024);
 std::uint64_t pos=from;
 while(pos<max){auto n=std::min<std::uint64_t>(b.size(),max-pos);if(!src.read_at(pos,std::span<std::byte>(b.data(),static_cast<size_t>(n))))return 0;
  for(std::uint64_t i=0;i+ r.end->bytes.size()<=n;i++)if(match(b.data()+i,*r.end))return pos+i+r.end->bytes.size();
  pos += n > r.end->bytes.size()? n-r.end->bytes.size()+1 : n;
 }
 return 0;
}
ScanResult scan(ISource&src,const std::vector<Rule>&rules,std::uint64_t start,std::uint64_t length,std::function<bool()>cancelled){
 ScanResult out{};out.source_size=src.size();if(start>src.size()){out.status="invalid_range";return out;}auto max=length?std::min(src.size(),start+length):src.size();const size_t chunk=4*1024*1024;size_t maxsig=1;for(auto&r:rules)maxsig=std::max(maxsig,r.start.bytes.size());
 std::vector<std::byte>b(chunk+maxsig);
 for(std::uint64_t pos=start;pos<max;){if(cancelled&&cancelled()){out.status="cancelled";break;}auto n=std::min<std::uint64_t>(chunk,max-pos);auto overlap=(pos+n<max)?maxsig-1:0;if(!src.read_at(pos,std::span<std::byte>(b.data(),static_cast<size_t>(n+overlap)))){out.status="source_read_error";break;}out.bytes_scanned+=n;
  for(auto&r:rules){auto sig=r.start.bytes.size();if(sig==0||sig>b.size())continue;for(std::uint64_t i=0;i+sig<=n+overlap;i++){if(!match(b.data()+i,r.start))continue;auto off=pos+i;Candidate c{};c.id=out.candidates.size()+1;c.rule_id=r.id;c.type=r.name;c.extension=r.extension;c.offset=off;c.name=r.id+"_"+std::to_string(off)+r.extension;c.extents={{off,0}};c.evidence.push_back("start_signature_match");
    std::uint64_t end=0;if(r.end)end=next_end(src,r,off+sig,std::min(max,off+r.max_size));if(r.end&&end){c.size=end-off;c.kind=MatchKind::StartEnd;c.confidence=90;c.evidence.push_back("end_signature_match");}
    else if(r.fixed_size){c.size=r.fixed_size;c.kind=MatchKind::FixedSize;c.confidence=85;c.evidence.push_back("fixed_size_rule");}
    else {c.size=std::min(r.max_size,max-off);c.kind=MatchKind::StartOnly;c.confidence=55;c.truncated=(c.size==r.max_size);c.evidence.push_back("size_inferred_from_rule_limit");}
    if(c.size>0&&c.offset+c.size<=max){c.extents[0].length=c.size;out.candidates.push_back(std::move(c));}
  }}
  pos+=n;
 }
 // de-duplicate exact (rule,offset)
 std::sort(out.candidates.begin(),out.candidates.end(),[](const auto& lhs,const auto& rhs){return std::tie(lhs.rule_id,lhs.offset,lhs.size)<std::tie(rhs.rule_id,rhs.offset,rhs.size);});
 std::vector<Candidate>u;for(auto&c:out.candidates)if(u.empty()||u.back().rule_id!=c.rule_id||u.back().offset!=c.offset)u.push_back(c);for(size_t i=0;i<u.size();i++)u[i].id=i+1;out.candidates=std::move(u);return out;
}
}
