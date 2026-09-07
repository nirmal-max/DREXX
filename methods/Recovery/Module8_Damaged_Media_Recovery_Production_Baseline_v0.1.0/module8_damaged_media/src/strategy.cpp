#include "media/strategy.hpp"
namespace media {Policy production_policy(){Policy p{};p.block_sectors=256;p.retries=2;p.split_min_sectors=1;p.reverse_pass=true;p.fill=0;return p;}}
