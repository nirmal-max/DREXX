#include "targeted/validator.hpp"
#include <vector>
#include <cstring>
namespace targeted {
static bool head(ISource&s,std::uint64_t o,std::vector<std::byte>&b){return s.read_at(o,std::span<std::byte>(b.data(),b.size()));}
bool validate_candidate(ISource&src,Candidate&c,std::function<bool()>cancelled){
 if(cancelled&&cancelled())return false;
 if(c.size==0||c.offset>src.size()||c.size>src.size()-c.offset)return false;
 std::vector<std::byte>b(64);auto n=std::min<std::uint64_t>(64,c.size);b.resize(static_cast<size_t>(n));if(!head(src,c.offset,b))return false;
 bool ok=true;
 if(c.rule_id=="pdf") ok=n>=5&&std::memcmp(b.data(),"%PDF-",5)==0;
 else if(c.rule_id=="jpeg") ok=n>=3&&std::to_integer<unsigned char>(b[0])==0xFF&&std::to_integer<unsigned char>(b[1])==0xD8&&std::to_integer<unsigned char>(b[2])==0xFF;
 else if(c.rule_id=="png") ok=n>=8&&std::memcmp(b.data(),"\x89PNG\r\n\x1a\n",8)==0;
 else if(c.rule_id=="zip"||c.rule_id=="docx"||c.rule_id=="xlsx"||c.rule_id=="pptx") ok=n>=4&&std::to_integer<unsigned char>(b[0])=='P'&&std::to_integer<unsigned char>(b[1])=='K';
 else if(c.rule_id=="mp3") ok=n>=3&&std::memcmp(b.data(),"ID3",3)==0;
 else if(c.rule_id=="mp4") ok=n>=8&&std::memcmp(b.data()+4,"ftyp",4)==0;
 if(ok){c.kind=MatchKind::Validated;c.confidence=std::min(99,c.confidence+15);c.evidence.push_back("format_header_validation");}
 else {c.confidence=std::max(0,c.confidence-30);c.evidence.push_back("format_validation_failed");}
 return ok;
}
}
