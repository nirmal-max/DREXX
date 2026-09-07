#include "media/map.hpp"
#include <fstream>
#include <cstdio>
#include <limits>
namespace media {
bool save_map(const Map&m,const std::string&p){
    if(m.sector_size==0 || m.sector_count!=m.sectors.size()) return false;
    auto tmp=p+".tmp";
    {
        std::ofstream f(tmp,std::ios::binary|std::ios::trunc);
        if(!f)return false;
        f<<"DMAP1 "<<m.sector_size<<" "<<m.sector_count<<"\n";
        for(auto&s:m.sectors)f<<(int)s.state<<" "<<s.attempts<<" "<<s.last_error<<"\n";
        if(!f)return false;
    }
    // Do not remove the last known-good map until the replacement is fully written.
    std::remove(p.c_str());
    return std::rename(tmp.c_str(),p.c_str())==0;
}
bool load_map(const std::string&p,Map&m){
    std::ifstream f(p);
    std::string magic;
    std::uint64_t sector_size=0,sector_count=0;
    if(!(f>>magic>>sector_size>>sector_count)||magic!="DMAP1"||sector_size==0)return false;
    // Prevent hostile/corrupt map files from forcing an impractical allocation.
    constexpr std::uint64_t kMaxSectors = (1ull<<34);
    if(sector_count>kMaxSectors || sector_count>std::numeric_limits<size_t>::max())return false;
    std::vector<Sector> sectors((size_t)sector_count);
    for(auto&s:sectors){
        int x;
        if(!(f>>x>>s.attempts>>s.last_error)||x<static_cast<int>(State::Unknown)||x>static_cast<int>(State::Failed))return false;
        s.state=(State)x;
    }
    m.sector_size=sector_size;
    m.sector_count=sector_count;
    m.sectors=std::move(sectors);
    return true;
}
}
