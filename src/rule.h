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
#include <vector>
#include <map>
#include <list>

#include <sys/poll.h>

#include "ndppd.h"

NDPPD_NS_BEGIN

class iface;
class proxy;

class rule {
public:
    static ptr<rule> create(const ptr<proxy>& pr, const address& addr, const ptr<iface>& ifa);

    static ptr<rule> create(const ptr<proxy>& pr, const address& addr, bool stc = true);

    const address& addr() const;

    ptr<iface> daughter() const;

    bool is_auto() const;

    bool check(const address& addr) const;

    static bool any_auto();

    static bool any_static();

    static bool any_iface();

    bool autovia() const;

    void autovia(bool val);

private:
    weak_ptr<rule> _ptr;

    weak_ptr<proxy> _pr;

    ptr<iface> _daughter;

    address _addr;

    bool _aut;

    static bool _any_aut;

    static bool _any_static;

    static bool _any_iface;

    bool _autovia;

    rule();
};

class interface {
public:
    // List of IPv6 addresses on this interface
    std::list<address> addresses;

    // Index of this interface
    int ifindex;

    // Name of this interface.
    std::string _name;

};

extern std::vector<interface> interfaces;

NDPPD_NS_END
