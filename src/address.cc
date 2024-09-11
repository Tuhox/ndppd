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
#include <string>
#include <vector>
#include <fstream>
#include <list>
#include <map>

#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <cctype>

#include <netinet/ip6.h>
#include <arpa/inet.h>

#include "ndppd.h"
#include "address.h"
#include "route.h"

NDPPD_NS_BEGIN

std::list<ptr<route> > address::_addresses;

int address::_ttl;

int address::_c_ttl;

address::address()
{
    reset();
}

address::address(const address& addr)
{
    _addr.s6_addr32[0] = addr._addr.s6_addr32[0];
    _addr.s6_addr32[1] = addr._addr.s6_addr32[1];
    _addr.s6_addr32[2] = addr._addr.s6_addr32[2];
    _addr.s6_addr32[3] = addr._addr.s6_addr32[3];

    _mask.s6_addr32[0] = addr._mask.s6_addr32[0];
    _mask.s6_addr32[1] = addr._mask.s6_addr32[1];
    _mask.s6_addr32[2] = addr._mask.s6_addr32[2];
    _mask.s6_addr32[3] = addr._mask.s6_addr32[3];
}

address::address(const ptr<address>& addr)
{
    _addr.s6_addr32[0] = addr->_addr.s6_addr32[0];
    _addr.s6_addr32[1] = addr->_addr.s6_addr32[1];
    _addr.s6_addr32[2] = addr->_addr.s6_addr32[2];
    _addr.s6_addr32[3] = addr->_addr.s6_addr32[3];

    _mask.s6_addr32[0] = addr->_mask.s6_addr32[0];
    _mask.s6_addr32[1] = addr->_mask.s6_addr32[1];
    _mask.s6_addr32[2] = addr->_mask.s6_addr32[2];
    _mask.s6_addr32[3] = addr->_mask.s6_addr32[3];
}

address::address(const std::string& str)
{
    parse_string(str);
}

address::address(const char* str)
{
    parse_string(str);
}

address::address(const in6_addr& addr)
{
    *this = addr;
}

address::address(const in6_addr& addr, const in6_addr& mask)
{
    _addr.s6_addr32[0] = addr.s6_addr32[0];
    _addr.s6_addr32[1] = addr.s6_addr32[1];
    _addr.s6_addr32[2] = addr.s6_addr32[2];
    _addr.s6_addr32[3] = addr.s6_addr32[3];

    _mask.s6_addr32[0] = mask.s6_addr32[0];
    _mask.s6_addr32[1] = mask.s6_addr32[1];
    _mask.s6_addr32[2] = mask.s6_addr32[2];
    _mask.s6_addr32[3] = mask.s6_addr32[3];
}

address::address(const in6_addr& addr, int pf)
{
    _addr.s6_addr32[0] = addr.s6_addr32[0];
    _addr.s6_addr32[1] = addr.s6_addr32[1];
    _addr.s6_addr32[2] = addr.s6_addr32[2];
    _addr.s6_addr32[3] = addr.s6_addr32[3];

    prefix(pf);
}

bool address::operator==(const address& addr) const
{
    return !(((_addr.s6_addr32[0] ^ addr._addr.s6_addr32[0]) & _mask.s6_addr32[0]) |
             ((_addr.s6_addr32[1] ^ addr._addr.s6_addr32[1]) & _mask.s6_addr32[1]) |
             ((_addr.s6_addr32[2] ^ addr._addr.s6_addr32[2]) & _mask.s6_addr32[2]) |
             ((_addr.s6_addr32[3] ^ addr._addr.s6_addr32[3]) & _mask.s6_addr32[3]));
}

bool address::operator!=(const address& addr) const
{
    return !!(((_addr.s6_addr32[0] ^ addr._addr.s6_addr32[0]) & _mask.s6_addr32[0]) |
              ((_addr.s6_addr32[1] ^ addr._addr.s6_addr32[1]) & _mask.s6_addr32[1]) |
              ((_addr.s6_addr32[2] ^ addr._addr.s6_addr32[2]) & _mask.s6_addr32[2]) |
              ((_addr.s6_addr32[3] ^ addr._addr.s6_addr32[3]) & _mask.s6_addr32[3]));
}

address& address::operator=(const address& addr)
{
    _ttl       = addr._ttl;
    _c_ttl     = addr._c_ttl;
    _addresses = addr._addresses;
    _addr      = addr._addr;
    _mask      = addr._mask;

    return *this;
}


bool address::is_empty() const
{
    if (_addr.s6_addr32[0] == 0 &&
        _addr.s6_addr32[1] == 0 &&
        _addr.s6_addr32[2] == 0 &&
        _addr.s6_addr32[3] == 0 &&
        _mask.s6_addr32[0] == 0xffffffff &&
        _mask.s6_addr32[1] == 0xffffffff &&
        _mask.s6_addr32[2] == 0xffffffff &&
        _mask.s6_addr32[3] == 0xffffffff)
        return true;

    return false;
}

void address::reset()
{
    _addr.s6_addr32[0] = 0;
    _addr.s6_addr32[1] = 0;
    _addr.s6_addr32[2] = 0;
    _addr.s6_addr32[3] = 0;

    _mask.s6_addr32[0] = 0xffffffff;
    _mask.s6_addr32[1] = 0xffffffff;
    _mask.s6_addr32[2] = 0xffffffff;
    _mask.s6_addr32[3] = 0xffffffff;
}

int address::prefix() const
{
    if (!_mask.s6_addr[0]) {
        return 0;
    }

    for (int p = 0; p < 128; p++) {
        int byi = p / 8, bii = 7 - (p % 8);

        if (!(_mask.s6_addr[byi]&  (1 << bii))) {
            return p;
        }
    }

    return 128;
}

void address::prefix(int pf)
{
    const unsigned char maskbit[] = {
        0x00, 0x80, 0xc0, 0xe0, 0xf0,
        0xf8, 0xfc, 0xfe, 0xff
    };

    if (pf >= 128) {
        _mask.s6_addr32[0] = 0xffffffff;
        _mask.s6_addr32[1] = 0xffffffff;
        _mask.s6_addr32[2] = 0xffffffff;
        _mask.s6_addr32[3] = 0xffffffff;
        return;
    } else {
        _mask.s6_addr32[0] = 0;
        _mask.s6_addr32[1] = 0;
        _mask.s6_addr32[2] = 0;
        _mask.s6_addr32[3] = 0;

        if (pf <= 0) {
            return;
        }
    }

    int offset = pf / 8, n;

    for (n = 0; n < offset; n++) {
        _mask.s6_addr[n] = 0xff;
    }

    _mask.s6_addr[offset] = maskbit[pf % 8];
}

const std::string address::to_string() const
{
    char buf[INET6_ADDRSTRLEN + 8];

    if (!inet_ntop(AF_INET6,& _addr, buf, INET6_ADDRSTRLEN))
        return "::1";

    // TODO: What to do about invalid ip?

    int p;

    if ((p = prefix()) < 128) {
        sprintf(buf + strlen(buf), "/%d", p);
    }

    return buf;
}

bool address::parse_string(const std::string& str)
{
    char buf[INET6_ADDRSTRLEN],* b;
    int sz;

    sz = 0;
    b  = buf;

    reset();

    const char* p = str.c_str();

    while (*p && isspace(*p))
        p++;

    while (*p) {
        if ((*p == '/') || isspace(*p)) {
            break;
        }

        if ((*p != ':') && !isxdigit(*p)) {
            return false;
        }

        if (sz >= (INET6_ADDRSTRLEN - 1)) {
            return false;
        }

        *b++ =* p++;

        sz++;
    }

    *b = '\0';

    if (inet_pton(AF_INET6, buf,& _addr) <= 0) {
        return false;
    }

    while (*p && isspace(*p)) {
        p++;
    }

    if (*p == '\0') {
        _mask.s6_addr32[0] = 0xffffffff;
        _mask.s6_addr32[1] = 0xffffffff;
        _mask.s6_addr32[2] = 0xffffffff;
        _mask.s6_addr32[3] = 0xffffffff;
        return true;
    }

    if (*p++ != '/')
        return false;

    while (*p && isspace(*p)) {
        p++;
    }

    sz = 0;
    b  = buf;

    while (*p) {
        if (!isdigit(*p)) {
            return false;
        }

        if (sz > 3) {
            return false;
        }

        *b++ =* p++;
        sz++;
    }

    *b = '\0';

    prefix(atoi(buf));

    return true;
}

address::operator std::string() const
{
    return to_string();
}

struct in6_addr& address::addr()
{
    return _addr;
}

const struct in6_addr& address::const_addr() const
{
    return _addr;
}

struct in6_addr& address::mask()
{
    return _mask;
}

bool address::is_multicast() const
{
    return _addr.s6_addr[0] == 0xff;
}

bool address::is_unicast() const
{
    if (_addr.s6_addr32[2] == 0 &&
        _addr.s6_addr32[3] == 0)
        return false;

    return _addr.s6_addr[0] != 0xff;
}

void address::add(const address& addr, const std::string& ifname)
{
    ptr<route> rt(new route(addr, ifname));
    // logger::debug() << "address::create() addr=" << addr << ", ifname=" << ifname;
    _addresses.push_back(rt);
}

std::list<ptr<route> >::iterator address::addresses_begin()
{
    return _addresses.begin();
}

std::list<ptr<route> >::iterator address::addresses_end()
{
    return _addresses.end();
}

void address::load(const std::string& path)
{
    // Hack to make sure the addresses are not freed prematurely.
    std::list<ptr<route> > tmp_addresses(_addresses);
    _addresses.clear();

    logger::debug() << "reading IP addresses";

    try {
        std::ifstream ifs;
        ifs.exceptions(std::ifstream::badbit | std::ifstream::failbit);
        ifs.open(path.c_str(), std::ios::in);
        ifs.exceptions(std::ifstream::badbit);

        while (!ifs.eof()) {
            char buf[1024];
            ifs.getline(buf, sizeof(buf));

            if (ifs.gcount() < 53) {
                if (ifs.gcount() > 0)
                    logger::debug() << "skipping entry (size=" << ifs.gcount() << ")";
                continue;
            }

            address addr;

            if (route::hexdec(buf, (unsigned char* )&addr.addr(), 16) != 16) {
                logger::warning() << "failed to load address (" << buf << ")";
                continue;
            }

            addr.prefix(128);

            std::string iface = route::token(buf + 45);

            address::add(addr, iface);

            logger::debug() << "found local addr=" << addr << ", iface=" << iface;
        }
    } catch (std::ifstream::failure & e) {
        logger::warning() << "Failed to parse IPv6 address data from '" << path << "'";
        logger::error() << e.what();
    }

    logger::debug() << "completed IP addresses load";
}

void address::update(int elapsed_time)
{
    if ((_c_ttl -= elapsed_time) <= 0) {
        load("/proc/net/if_inet6");
        _c_ttl = _ttl;
    }
}

int address::ttl()
{
    return _ttl;
}

void address::ttl(int ttl)
{
    _ttl = ttl;
}

NDPPD_NS_END
