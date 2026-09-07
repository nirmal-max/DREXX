#include "fsrecover/providers.hpp"
#include "fsrecover/detect.hpp"
#include "fsrecover/partition.hpp"
#include "fsrecover/source.hpp"
#include <functional>
namespace fsr {
Result reconstruct(ISource&s,std::function<bool()>cancelled){
 Result r{};r.partitions=analyze_partitions(s,r.warnings);if(r.partitions.empty()){r.status="no_partitions";return r;}
 for(auto&p:r.partitions){auto g=detect(s,p);if(g.type==FsType::Unknown){r.warnings.push_back("partition "+std::to_string(p.index)+": unknown filesystem");continue;}r.geometry=g;bool ok=false;switch(g.type){case FsType::NTFS:ok=scan_ntfs(s,g,r.objects,r.health,cancelled);break;case FsType::FAT12:case FsType::FAT16:case FsType::FAT32:ok=scan_fat(s,g,r.objects,r.health,cancelled);break;case FsType::exFAT:ok=scan_exfat(s,g,r.objects,r.health,cancelled);break;case FsType::EXT2:case FsType::EXT3:case FsType::EXT4:ok=scan_ext(s,g,r.objects,r.health,cancelled);break;default:break;}if(ok){r.status=r.objects.empty()?"partial":"success";break;}}
 if(r.status=="invalid")r.status="unsupported_filesystem";return r;
}
}
