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

#include <sys/poll.h>

#include "ndppd.h"

NDPPD_NS_BEGIN

class iface;
class rule;

class proxy {
public:
    static ptr<proxy> create(const ptr<iface>& ifa, bool promiscuous);

    static ptr<proxy> find_aunt(const std::string& ifname, const address& taddr);

    static ptr<proxy> open(const std::string& ifn, bool promiscuous);

    ptr<session> find_or_create_session(const address& taddr);

    void handle_advert(const address& saddr, const address& taddr, const std::string& ifname, bool use_via);

    void handle_stateless_advert(const address& saddr, const address& taddr, const std::string& ifname, bool use_via);

    void handle_solicit(const address& saddr, const address& taddr, const std::string& ifname);

    void remove_session(const ptr<session>& se);

    ptr<rule> add_rule(const address& addr, const ptr<iface>& ifa, bool autovia);

    ptr<rule> add_rule(const address& addr, bool aut = false);

    std::list<ptr<rule> >::iterator rules_begin();

    std::list<ptr<rule> >::iterator rules_end();

    const ptr<iface>& ifa() const;

    bool promiscuous() const;

    bool router() const;

    void router(bool val);

    bool autowire() const;

    void autowire(bool val);

    int retries() const;

    void retries(int val);

    bool keepalive() const;

    void keepalive(bool val);

    int timeout() const;

    void timeout(int val);

    int ttl() const;

    void ttl(int val);

    int deadtime() const;

    void deadtime(int val);

private:
    static std::list<ptr<proxy> > _list;

    weak_ptr<proxy> _ptr;

    ptr<iface> _ifa;

    std::list<ptr<rule> > _rules;

    std::list<ptr<session> > _sessions;

    bool _promiscuous;

    bool _router;

    bool _autowire;

    int _retries;

    bool _keepalive;

    int _ttl, _deadtime, _timeout;

    proxy();
};

NDPPD_NS_END
