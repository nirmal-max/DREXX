#include "fragment/signatures.hpp"
#include <array>
#include <cstring>
namespace frag{
FileType parse_type(const std::string&s){if(s=="pdf")return FileType::PDF;if(s=="jpeg"||s=="jpg")return FileType::JPEG;if(s=="png")return FileType::PNG;if(s=="zip")return FileType::ZIP;return FileType::Unknown;}
static bool match(FileType t,const std::byte*p,size_t n){if(t==FileType::PDF)return n>=5&&std::memcmp(p,"%PDF-",5)==0;if(t==FileType::JPEG)return n>=3&&std::to_integer<unsigned char>(p[0])==0xFF&&std::to_integer<unsigned char>(p[1])==0xD8&&std::to_integer<unsigned char>(p[2])==0xFF;if(t==FileType::PNG)return n>=8&&std::memcmp(p,"\x89PNG\r\n\x1a\n",8)==0;if(t==FileType::ZIP)return n>=4&&std::memcmp(p,"PK\x03\x04",4)==0;return false;}
std::vector<Fragment> find_anchors(ISource&s,FileType t,std::uint64_t block,std::uint64_t max_scan){std::vector<Fragment>o;std::vector<std::byte>b(4*1024*1024);std::uint64_t end=std::min(max_scan,s.size());for(std::uint64_t p=0;p<end;){auto n=std::min<std::uint64_t>(b.size(),end-p);if(!s.read_at(p,std::span<std::byte>(b.data(),(size_t)n)))break;for(std::uint64_t i=0;i<n;i++)if(match(t,b.data()+i,(size_t)(n-i))){Fragment f{};f.id=o.size()+1;f.physical=p+i;f.length=block;f.file_offset=0;f.type=t;f.anchor_score=65;f.evidence.push_back("format_start_signature");o.push_back(f);}p+=n;}return o;}
}
