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
#pragma once
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include "ndppd.h"

NDPPD_NS_BEGIN

uint16_t icmp6_sum(const struct ip6_hdr* hdr, const void* payload, int size);

NDPPD_NS_END
