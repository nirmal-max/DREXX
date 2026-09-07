#include "targeted/signature.hpp"
#include "targeted/scanner.hpp"
#include "targeted/validator.hpp"
#include <cassert>
#include <vector>
#include <algorithm>
#include <iostream>
class Mem final: public targeted::ISource{
 std::vector<std::byte>d_;
public: Mem(std::vector<std::byte>d):d_(std::move(d)){}
 bool read_at(std::uint64_t o,std::span<std::byte>b)override{if(o>d_.size()||b.size()>d_.size()-o)return false;std::copy(d_.begin()+o,d_.begin()+o+b.size(),b.begin());return true;}
 std::uint64_t size()const override{return d_.size();}std::string identity()const override{return "mem";}
};
int main(){
 auto rules=targeted::built_in_rules();
 std::vector<std::byte>d(4096);d[100]=std::byte{0xFF};d[101]=std::byte{0xD8};d[102]=std::byte{0xFF};d[300]=std::byte{0xFF};d[301]=std::byte{0xD9};
 Mem m(std::move(d));auto r=targeted::scan(m,rules,0,0);assert(!r.candidates.empty());bool found=false;for(auto&c:r.candidates)if(c.rule_id=="jpeg"&&c.offset==100){found=true;auto copy=c;assert(targeted::validate_candidate(m,copy));}assert(found);
 auto ids=targeted::list_rule_ids();assert(std::find(ids.begin(),ids.end(),"pdf")!=ids.end());std::cout<<"all tests passed\n";
}
