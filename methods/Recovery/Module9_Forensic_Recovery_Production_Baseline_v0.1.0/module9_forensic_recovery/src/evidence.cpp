#include "forensic/acquire.hpp"
#include "forensic/sha256.hpp"
#include <fstream>
#include <filesystem>
namespace forensic {
bool acquire_file(const std::string&src,const std::string&dst,std::uint64_t&size,std::string&e){
 std::error_code ec;
 auto a=std::filesystem::weakly_canonical(src,ec),b=std::filesystem::weakly_canonical(dst,ec);
 if(!ec&&a==b){e="source and evidence destination resolve to the same path";return false;}
 std::ifstream in(src,std::ios::binary);if(!in){e="cannot open source read-only";return false;}
 std::ofstream out(dst,std::ios::binary|std::ios::trunc);if(!out){e="cannot create evidence copy";return false;}
 char buf[1024*1024];size=0;while(in){in.read(buf,sizeof(buf));auto n=in.gcount();if(n>0){out.write(buf,n);size+=(std::uint64_t)n;}if(in.bad()){e="source read error";return false;}}if(!out){e="evidence write error";return false;}return true;
}
HashResult hash_file(const std::string&p){HashResult r{};std::string e;r.sha256=sha256_file(p,r.size,e);r.ok=e.empty();return r;}
}
