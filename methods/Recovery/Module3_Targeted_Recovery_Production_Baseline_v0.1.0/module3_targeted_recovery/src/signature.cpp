#include "targeted/signature.hpp"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>
namespace targeted {
static std::vector<std::uint8_t> hx(const std::string&s){
 std::vector<std::uint8_t>o;std::string x;for(char c:s)if(!std::isspace(static_cast<unsigned char>(c)))x+=c;
 if(x.size()%2)return{};
 for(size_t i=0;i<x.size();i+=2){auto cv=[](char c)->int{if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;if(c>='A'&&c<='F')return c-'A'+10;return -1;};int a=cv(x[i]),b=cv(x[i+1]);if(a<0||b<0)return{};o.push_back(static_cast<std::uint8_t>((a<<4)|b));}return o;
}
static Rule r(std::string id,std::string name,std::string ext,std::string sig,std::uint64_t max=64ULL*1024*1024){
 Rule x{};x.id=id;x.name=name;x.extension=ext;x.group="common";x.start.bytes=hx(sig);x.start.mask.assign(x.start.bytes.size(),0xFF);x.max_size=max;return x;
}
std::vector<Rule> built_in_rules(){
 auto pdf=r("pdf","PDF",".pdf","255044462D",512ULL*1024*1024);
 auto jpg=r("jpeg","JPEG",".jpg","FFD8FF",128ULL*1024*1024);
 jpg.end=Signature{hx("FFD9"),{0xFF,0xFF},0,0};
 auto png=r("png","PNG",".png","89504E470D0A1A0A",512ULL*1024*1024);
 auto zip=r("zip","ZIP",".zip","504B0304",1024ULL*1024*1024);
 auto docx=zip;docx.id="docx";docx.name="Office Open XML";docx.extension=".docx";
 auto xlsx=zip;xlsx.id="xlsx";xlsx.name="Office Open XML Spreadsheet";xlsx.extension=".xlsx";
 auto pptx=zip;pptx.id="pptx";pptx.name="Office Open XML Presentation";pptx.extension=".pptx";
 auto mp3=r("mp3","MP3",".mp3","494433",256ULL*1024*1024);
 auto mp4=r("mp4","MP4/MPEG-4",".mp4","66747970",1024ULL*1024*1024);
 return {pdf,jpg,png,zip,docx,xlsx,pptx,mp3,mp4};
}
std::vector<std::string> list_rule_ids(){std::vector<std::string>o;for(auto&r:built_in_rules())o.push_back(r.id);return o;}
std::vector<Rule> load_rules_json(const std::string&path,std::string&error){
 std::ifstream f(path);if(!f){error="cannot open rules file";return{};}std::string s((std::istreambuf_iterator<char>(f)),{});
 // Intentionally tiny, dependency-free JSON-like loader: accepts one rule per line:
 // id|name|extension|start_hex|max_size
 std::vector<Rule>o;std::istringstream in(s);std::string line;while(std::getline(in,line)){if(line.empty()||line[0]=='#')continue;std::vector<std::string>v;std::stringstream ss(line);std::string q;while(std::getline(ss,q,'|'))v.push_back(q);if(v.size()<4)continue;auto x=r(v[0],v[1],v[2],v[3]);if(v.size()>4)try{x.max_size=std::stoull(v[4]);}catch(...){error="invalid max size in rules";return{};}if(x.start.bytes.empty()){error="invalid signature in rules";return{};}o.push_back(x);}return o;
}
}
