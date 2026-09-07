#pragma once
#include <cstdint>
#include <memory>
#include <span>
#include <string>
namespace media {
class ISource{public:virtual~ISource()=default;virtual bool read_at(std::uint64_t,std::span<std::byte>)=0;virtual std::uint64_t size()const=0;};
std::unique_ptr<ISource> open_source(const std::string&,std::string&);
}
