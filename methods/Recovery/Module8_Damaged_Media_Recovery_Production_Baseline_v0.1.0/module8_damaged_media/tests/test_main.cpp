#include "media/source.hpp"
#include "media/imager.hpp"
#include <cassert>
#include <fstream>
int main(){std::ofstream f("/tmp/media_test_src.bin",std::ios::binary);for(int i=0;i<4096;i++)f.put((char)(i&255));f.close();std::string e;auto s=media::open_source("/tmp/media_test_src.bin",e);assert(s);auto r=media::image(*s,"/tmp/media_test_img.bin","/tmp/media_test.map",media::Policy{});assert(r.status=="complete");assert(r.stats.good==8);return 0;}
