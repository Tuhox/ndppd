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
#pragma once

#include <string>
#include <list>
#include <memory>

#include "ndppd.h"

NDPPD_NS_BEGIN

class route {
public:
    static ptr<route> create(const address& addr, const std::string& ifname);

    static ptr<route> find(const address& addr);

    static ptr<iface> find_and_open(const address& addr);

    static void load(const std::string& path);

    static void update(int elapsed_time);

    static int ttl();

    static void ttl(int ttl);

    const std::string& ifname() const;

    const address& addr() const;

    ptr<iface> ifa();

    route(const address& addr, const std::string& ifname);

    static size_t hexdec(const char* str, unsigned char* buf, size_t size);

    static std::string token(const char* str);

private:
    static int _ttl;

    static int _c_ttl;

    address _addr;

    std::string _ifname;

    ptr<iface> _ifa;

    static std::list<ptr<route> > _routes;

};

NDPPD_NS_END
