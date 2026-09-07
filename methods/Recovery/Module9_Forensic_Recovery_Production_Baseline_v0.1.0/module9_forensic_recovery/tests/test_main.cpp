#include "forensic/sha256.hpp"
#include "forensic/case.hpp"
#include <cassert>
#include <fstream>
int main(){std::ofstream f("/tmp/f9.txt");f<<"abc";f.close();std::uint64_t n=0;std::string e;auto h=forensic::sha256_file("/tmp/f9.txt",n,e);assert(h=="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");assert(n==3);forensic::Case c;assert(forensic::init_case("C1","examiner","test",c,e));assert(c.events.size()==1);assert(forensic::append_event(c,"analysis","examiner","scan"));assert(c.events.size()==2);return 0;}
