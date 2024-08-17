// ndppd - NDP Proxy Daemon
// Copyright (C) 2011  Daniel Adolfsson <daniel@priv.nu>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
//
// file author: Sergey E. Kolesnikov <rockingdemon@gmail.com>
#include <cstdint>
#include <netinet/ip6.h>
#include "cksum.h"

NDPPD_NS_BEGIN

uint_fast32_t partial_sum(const void* data, int size)
{
    const uint16_t* wend= (const uint16_t*) data + size / 2;
    uint_fast32_t accum = 0;
    for (const uint16_t* wdata=(const uint16_t*) data; wdata < wend; wdata++) {
        accum += *wdata;
    }
    if (size & 1) {
        accum += *((const uint8_t*) data + size - 1);
    }
    return accum;
}

uint16_t icmp6_sum(const ip6_hdr* hdr, const void* payload, int size)
{
    uint_fast32_t accum = partial_sum(payload, size);
    accum += partial_sum(&hdr->ip6_src, sizeof(struct in6_addr));
    accum += partial_sum(&hdr->ip6_dst, sizeof(struct in6_addr));
    accum += hdr->ip6_plen;
    accum += htons(hdr->ip6_nxt); // calculated as 16-bit network order word
    return ~((accum >> 16) + (accum & 0xffff));
}

NDPPD_NS_END
