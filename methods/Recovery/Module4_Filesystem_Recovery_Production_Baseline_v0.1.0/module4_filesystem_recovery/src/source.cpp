#include "fsrecover/source.hpp"
#include <fstream>
#include <limits>
#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#endif
namespace fsr {
class FileSource final: public ISource{
 std::ifstream f_;std::uint64_t n_{};std::string id_;
public:
 FileSource(const std::string&p,std::string&e){f_.open(p,std::ios::binary);if(!f_){e="cannot open source";return;}f_.seekg(0,std::ios::end);auto x=f_.tellg();if(x<0){e="cannot size source";return;}n_=static_cast<std::uint64_t>(x);f_.seekg(0);id_=p+":"+std::to_string(n_);}
 bool read_at(std::uint64_t o,std::span<std::byte>b)override{if(o>n_||b.size()>n_-o)return false;f_.clear();f_.seekg(static_cast<std::streamoff>(o));if(!f_)return false;f_.read(reinterpret_cast<char*>(b.data()),static_cast<std::streamsize>(b.size()));return f_.gcount()==static_cast<std::streamsize>(b.size());}
 std::uint64_t size()const override{return n_;}std::string identity()const override{return id_;}
};
#ifdef _WIN32
class DeviceSource final: public ISource{
 HANDLE h_=INVALID_HANDLE_VALUE;std::uint64_t n_{};std::string id_;
public:
 DeviceSource(const std::string&p,std::string&e){h_=CreateFileA(p.c_str(),GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,OPEN_EXISTING,FILE_FLAG_RANDOM_ACCESS,nullptr);if(h_==INVALID_HANDLE_VALUE){e="cannot open physical device read-only";return;}GET_LENGTH_INFORMATION li{};DWORD got{};if(!DeviceIoControl(h_,IOCTL_DISK_GET_LENGTH_INFO,nullptr,0,&li,sizeof(li),&got,nullptr)){e="cannot query device size";CloseHandle(h_);h_=INVALID_HANDLE_VALUE;return;}n_=static_cast<std::uint64_t>(li.Length.QuadPart);id_=p+":"+std::to_string(n_);}
 ~DeviceSource(){if(h_!=INVALID_HANDLE_VALUE)CloseHandle(h_);}
 bool read_at(std::uint64_t o,std::span<std::byte>b)override{
  if(o>n_||b.size()>n_-o)return false;
  if(b.empty())return true;
  constexpr std::size_t max_chunk=static_cast<std::size_t>(std::numeric_limits<DWORD>::max());
  LARGE_INTEGER li{};li.QuadPart=static_cast<LONGLONG>(o);
  if(!SetFilePointerEx(h_,li,nullptr,FILE_BEGIN))return false;
  std::size_t done=0;
  while(done<b.size()){
   const DWORD request=static_cast<DWORD>(std::min(b.size()-done,max_chunk));
   DWORD got=0;
   if(!ReadFile(h_,b.data()+done,request,&got,nullptr)||got!=request)return false;
   done+=got;
  }
  return true;
 }
 std::uint64_t size()const override{return n_;}std::string identity()const override{return id_;}
};
#endif
std::unique_ptr<ISource> open_source(const std::string&p,std::string&e){
#ifdef _WIN32
 if(p.rfind(R"(\\.\PhysicalDrive)",0)==0){auto x=std::make_unique<DeviceSource>(p,e);if(!e.empty())return{};return x;}
#endif
 auto x=std::make_unique<FileSource>(p,e);if(!e.empty())return{};return x;
}
}
