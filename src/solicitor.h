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

#include "ndppd.h"
#include <netinet/ether.h>
#include <netinet/if_ether.h>

NDPPD_NS_BEGIN
class solicitor;
logger& operator<<(logger& log, const solicitor& sol);

class solicitor {
public:
    solicitor(const address& addr, const ether_addr& hwaddr)
        : _addr(addr), _hwaddr(hwaddr) { }

    const ether_addr& hwaddr() {return _hwaddr;}
    const address& addr() {return _addr;}
    bool is(const address& addr, const ether_addr& hwaddr);
private:
    friend logger& operator<<(logger& log, const solicitor& sol);
    const address _addr;
    const ether_addr _hwaddr;
};

NDPPD_NS_END
