#include "quick/recovery.hpp"
#include "quick/source.hpp"
#include "quick/partition.hpp"
#include "quick/filesystem.hpp"
#include "quick/ntfs.hpp"
#include "quick/fat.hpp"
#include "quick/exfat.hpp"
namespace quick {
ScanResult run_quick_scan(const std::string& path,std::function<bool()>cancelled){
    ScanResult r{};std::string e;auto src=open_source(path,e);if(!src){r.status=JobStatus::SourceReadError;r.message=e;return r;}
    r.source.size=src->size();r.source.identity=src->identity();r.partitions=analyze_partitions(*src,r.warnings);
    for(const auto&p:r.partitions){if(cancelled&&cancelled()){r.status=JobStatus::Cancelled;return r;}auto fs=detect_filesystem(*src,p);if(fs.type==FsType::Unknown){r.warnings.push_back("partition "+std::to_string(p.index)+": unsupported/unknown filesystem");continue;}
        bool ok=false;switch(fs.type){case FsType::NTFS:ok=NtfsProvider::scan(*src,fs,r.candidates,r.warnings,cancelled);break;case FsType::FAT12:case FsType::FAT16:case FsType::FAT32:ok=FatProvider::scan(*src,fs,r.candidates,r.warnings,cancelled);break;case FsType::exFAT:ok=ExfatProvider::scan(*src,fs,r.candidates,r.warnings,cancelled);break;default:break;}if(!ok&&r.status==JobStatus::InvalidInput)r.status=JobStatus::CorruptFilesystem;}
    if(r.status==JobStatus::InvalidInput)
        r.status=r.candidates.empty()?JobStatus::NoRecoverableMetadata:JobStatus::Success;
    return r;
}
bool recover_candidate(const std::string&path,const Candidate&c,const std::string&dest,std::string&error,std::function<bool()>cancelled){
    std::string e;auto src=open_source(path,e);if(!src){error=e;return false;}if(c.filesystem==FsType::NTFS)return NtfsProvider::recover(*src,c,dest,error,cancelled);if(c.filesystem==FsType::FAT12||c.filesystem==FsType::FAT16||c.filesystem==FsType::FAT32)return FatProvider::recover(*src,c,dest,error,cancelled);if(c.filesystem==FsType::exFAT)return ExfatProvider::recover(*src,c,dest,error,cancelled);error="unsupported filesystem";return false;
}
}
