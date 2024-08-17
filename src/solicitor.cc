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
//
#include <netinet/ether.h>
#include "ndppd.h"
#include "solicitor.h"
NDPPD_NS_BEGIN

logger& operator<<(logger& log, const solicitor& sol)
{
    char buff[18];
    ether_ntoa_r(&sol._hwaddr, buff);
    log
            << "solicitor{addr=" << sol._addr.to_string()
            << ", hwaddr=" << buff
            << "}";
    return log;
}

bool operator== (const ether_addr& a1, const ether_addr& a2)
{
    bool res = true;
    for (int i=0; i<ETH_ALEN && res; i++) {
        res = a1.ether_addr_octet[i] == a2.ether_addr_octet[i];
    }
    return res;
}

bool solicitor::is(const ndppd::address& addr, const ether_addr& hwaddr)
{
    return _addr==addr && _hwaddr==hwaddr;
}
NDPPD_NS_END
