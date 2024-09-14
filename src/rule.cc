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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>

#include "ndppd.h"
#include "rule.h"
#include "proxy.h"
#include "iface.h"

NDPPD_NS_BEGIN

std::vector<interface> interfaces;

bool rule::_any_aut = false;

bool rule::_any_iface = false;

bool rule::_any_static = false;

rule::rule()
{
}

ptr<rule> rule::create(const ptr<proxy>& pr, const address& addr, const ptr<iface>& ifa)
{
    ptr<rule> ru(new rule());
    ru->_ptr  = ru;
    ru->_pr   = pr;
    ru->_daughter  = ifa;
    ru->_addr = addr;
    ru->_aut  = false;
    _any_iface = true;
    unsigned int ifindex;

    ifindex = if_nametoindex(pr->ifa()->name().c_str());
#ifdef WITH_ND_NETLINK
    if_add_to_list(ifindex, pr->ifa());
#endif
    ifindex = if_nametoindex(ifa->name().c_str());
#ifdef WITH_ND_NETLINK
    if_add_to_list(ifindex, ifa);
#else
    (void)ifindex;
#endif

    logger::debug() << "rule::create() if=" << pr->ifa()->name() << ", slave=" << ifa->name() << ", addr=" << addr;

    return ru;
}

ptr<rule> rule::create(const ptr<proxy>& pr, const address& addr, bool aut)
{
    ptr<rule> ru(new rule());
    ru->_ptr   = ru;
    ru->_pr    = pr;
    ru->_addr  = addr;
    ru->_aut   = aut;
    _any_aut   = _any_aut || aut;

    if (aut == false)
        _any_static = true;

    logger::debug()
        << "rule::create() if=" << pr->ifa()->name().c_str() << ", addr=" << addr
        << ", auto=" << (aut ? "yes" : "no");

    return ru;
}

const address& rule::addr() const
{
    return _addr;
}

ptr<iface> rule::daughter() const
{
    return _daughter;
}

bool rule::is_auto() const
{
    return _aut;
}

bool rule::autovia() const
{
    return _autovia;
}

void rule::autovia(bool val)
{
    _autovia = val;
}

bool rule::any_auto()
{
    return _any_aut;
}

bool rule::any_iface()
{
    return _any_iface;
}

bool rule::any_static()
{
    return _any_static;
}

bool rule::check(const address& addr) const
{
    return _addr == addr;
}

NDPPD_NS_END
