// ============================================================================
// CanId.cpp —— 只为了 formatCanId：日志里要一眼看出是 11 位还是 29 位
// ============================================================================
#include "CanId.h"

#include <cstdio>

namespace doip
{

std::string formatCanId (std::uint32_t id)
{
    char b[16];
    if (isExtendedId (id))
        std::snprintf (b, sizeof (b), "0x%08X", static_cast<unsigned> (id));
    else
        std::snprintf (b, sizeof (b), "0x%03X", static_cast<unsigned> (id));
    return std::string (b);
}

} // namespace doip
