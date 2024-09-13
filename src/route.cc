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
#include <list>
#include <memory>
#include <fstream>

#include "ndppd.h"
#include "route.h"

NDPPD_NS_BEGIN

std::list<ptr<route> > route::_routes;

int route::_ttl;

int route::_c_ttl;

route::route(const address& addr, const std::string& ifname) :
    _addr(addr), _ifname(ifname)
{
}

size_t route::hexdec(const char* str, unsigned char* buf, size_t size)
{
    for (size_t i = 0; ; i++) {
        if (i >= size) {
            return i;
        }

        char c1 = tolower(str[i*  2]), c2 = tolower(str[i*  2 + 1]);

        if (!isxdigit(c1) || !isxdigit(c2)) {
            return i;
        }

        if ((c1 >= '0') && (c1 <= '9')) {
            buf[i] = (c1 - '0') << 4;
        } else {
            buf[i] = ((c1 - 'a') + 10) << 4;
        }

        if ((c2 >= '0') && (c2 <= '9')) {
            buf[i] |= c2 - '0';
        } else {
            buf[i] |= (c2 - 'a') + 10;
        }
    }
}

std::string route::token(const char* str)
{
    while (*str && isspace(*str)) {
        str++;
    }

    if (!*str) {
        return "";
    }

    std::stringstream ss;

    while (*str && !isspace(*str)) {
        ss <<* str++;
    }

    return ss.str();
}

void route::load(const std::string& path)
{
    // Hack to make sure the interfaces are not freed prematurely.
    std::list<ptr<route> > tmp_routes(_routes);
    _routes.clear();

    logger::debug() << "reading routes";

    try {
        std::ifstream ifs;
        ifs.exceptions(std::ifstream::badbit | std::ifstream::failbit);
        ifs.open(path.c_str(), std::ios::in);
        ifs.exceptions(std::ifstream::badbit);

        while (!ifs.eof()) {
            char buf[1024];
            ifs.getline(buf, sizeof(buf));

            if (ifs.gcount() < 149) {
                continue;
            }

            address addr;

            unsigned char pfx;

            if (route::hexdec(buf, (unsigned char* )&addr.addr(), 16) != 16) {
                // TODO: Warn here?
                continue;
            }

            if (route::hexdec(buf + 33,& pfx, 1) != 1) {
                // TODO: Warn here?
                continue;
            }

            addr.prefix((int)pfx);

            route::create(addr, route::token(buf + 141));
        }
    } catch (std::ifstream::failure & e) {
        logger::warning() << "Failed to parse IPv6 routing data from '" << path << "'";
        logger::error() << e.what();
    }
}

void route::update(int elapsed_time)
{
    if ((_c_ttl -= elapsed_time) <= 0) {
        load("/proc/net/ipv6_route");
        _c_ttl = _ttl;
    }
}

ptr<route> route::create(const address& addr, const std::string& ifname)
{
    ptr<route> rt(new route(addr, ifname));
    // logger::debug() << "route::create() addr=" << addr << ", ifname=" << ifname;
    _routes.push_back(rt);
    return rt;
}

ptr<route> route::find(const address& addr)
{
    for (std::list<ptr<route> >::iterator it = _routes.begin();
            it != _routes.end(); it++) {
        if ((*it)->addr() == addr)
            return *it;
    }

    return ptr<route>();
}

ptr<iface> route::find_and_open(const address& addr)
{
    ptr<route> rt;

    if ((rt = find(addr))) {
        return rt->ifa();
    }

    return ptr<iface>();
}

const std::string& route::ifname() const
{
    return _ifname;
}

ptr<iface> route::ifa()
{
    if (!_ifa) {
        logger::debug() << "router::ifa() opening interface '" << _ifname << "'";
        return _ifa = iface::open_ifd(_ifname);
    }

    return ptr<iface>();
}

const address& route::addr() const
{
    return _addr;
}

int route::ttl()
{
    return _ttl;
}

void route::ttl(int ttl)
{
    _ttl = ttl;
}

NDPPD_NS_END
