#include "fsrecover/source.hpp"
#include "fsrecover/reconstruction.hpp"
#include "fsrecover/json.hpp"
#include <fstream>
#include <iostream>
int main(int argc,char**argv){
 std::string source,out;
 for(int i=1;i<argc;i++){
  std::string a=argv[i];
  if(a=="--source"&&i+1<argc)source=argv[++i];
  else if(a=="--output"&&i+1<argc)out=argv[++i];
  else if(a=="--help"){std::cout<<"fsrecover --source <image|\\\\.\\PhysicalDriveN> [--output result.json]\\n";return 0;}
  else{std::cerr<<"unknown argument: "<<a<<"\n";return 2;}
 }
 if(source.empty()){std::cerr<<"--source required\n";return 2;}
 std::string e;auto s=fsr::open_source(source,e);if(!s){std::cerr<<e<<"\n";return 3;}
 auto r=fsr::reconstruct(*s);auto j=fsr::to_json(r);
 if(out.empty())std::cout<<j<<"\n";
 else{
  std::ofstream f(out,std::ios::binary|std::ios::trunc);
  if(!f){std::cerr<<"cannot write output\n";return 4;}
  f<<j<<'\n';
  f.flush();
  if(!f){std::cerr<<"cannot finalize output\n";return 4;}
 }
 return r.status=="success"?0:1;
}
