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

#include "ndppd.h"

#include "proxy.h"
#include "route.h"
#include "iface.h"
#include "rule.h"
#include "session.h"

NDPPD_NS_BEGIN

static address all_nodes = address("ff02::1");

std::list<ptr<proxy> > proxy::_list;

proxy::proxy() :
    _promiscuous(false), _router(true), _autowire(false), _retries(3), _keepalive(true), _ttl(30000), _deadtime(3000), _timeout(500)
{
}

ptr<proxy> proxy::find_aunt(const std::string& ifname, const address& taddr)
{
    for (std::list<ptr<proxy> >::iterator sit = _list.begin();
            sit != _list.end(); sit++)
    {
        ptr<proxy> pr = (*sit);

        bool has_addr = false;
        for (std::list<ptr<rule> >::iterator it = pr->_rules.begin(); it != pr->_rules.end(); it++) {
            ptr<rule> ru = *it;

            if (ru->addr() == taddr) {
                has_addr = true;
                break;
            }
        }

        if (has_addr == false) {
            continue;
        }

        if (pr->ifa() && pr->ifa()->name() == ifname)
            return pr;
    }

    return ptr<proxy>();
}

ptr<proxy> proxy::create(const ptr<iface>& ifa, bool promiscuous)
{
    ptr<proxy> pr(new proxy());
    pr->_ptr = pr;
    pr->_ifa = ifa;
    pr->_promiscuous = promiscuous;

    _list.push_back(pr);

    ifa->add_serves(pr);

    logger::debug() << "proxy::create() if=" << ifa->name();

    return pr;
}

ptr<proxy> proxy::open(const std::string& ifname, bool promiscuous)
{
    ptr<iface> ifa = iface::open_pfd(ifname, promiscuous);

    if (!ifa) {
        return ptr<proxy>();
    }

    return create(ifa, promiscuous);
}

ptr<session> proxy::find_or_create_session(const address& taddr)
{
    // Let's check this proxy's list of sessions to see if we can
    // find one with the same target address.

    for (std::list<ptr<session> >::iterator sit = _sessions.begin();
            sit != _sessions.end(); sit++) {

        if ((*sit)->taddr() == taddr)
            return (*sit);
    }

    ptr<session> se;

    // Since we couldn't find a session that matched, we'll try to find
    // a matching rule instead, and then set up a new session.

    for (std::list<ptr<rule> >::iterator it = _rules.begin();
            it != _rules.end(); it++) {
        ptr<rule> ru = *it;

        logger::debug() << "checking " << ru->addr() << " against " << taddr;

        if (ru->addr() == taddr) {
            if (!se) {
                se = session::create(_ptr, taddr, _autowire, _keepalive, _retries);
            }

            if (ru->is_auto()) {
                ptr<route> rt = route::find(taddr);

                if (rt->ifname() == _ifa->name()) {
                    logger::debug() << "skipping route since it's using interface " << rt->ifname();
                } else {
                    ptr<iface> ifa = rt->ifa();

                    if (ifa && (ifa != ru->daughter())) {
                        se->add_iface(ifa);
                    }
                }
            } else if (!ru->daughter()) {
                // This rule doesn't have an interface, and thus we'll consider
                // it "static" and immediately send the response.
                se->handle_advert();
                return se;

            } else {

                ptr<iface> ifa = ru->daughter();
                se->add_iface(ifa);

                #ifdef WITH_ND_NETLINK
                if (if_addr_find(ifa->name(), &taddr.const_addr())) {
                    logger::debug() << "Sending NA out " << ifa->name();
                    se->add_iface(_ifa);
                    se->handle_advert();
                }
                #endif
            }
        }
    }

    if (se) {
        _sessions.push_back(se);
    }

    return se;
}

void proxy::handle_advert(const address& saddr, const address& taddr, const std::string& ifname, bool use_via)
{
    // If a session exists then process the advert in the context of the session
    for (std::list<ptr<session> >::iterator s_it = _sessions.begin();
            s_it != _sessions.end(); s_it++)
    {
        const ptr<session> sess = *s_it;

        if ((sess->taddr() == taddr)) {
            sess->handle_advert(saddr, ifname, use_via);
        }
    }
}

void proxy::handle_stateless_advert(const address& saddr, const address& taddr, const std::string& ifname, bool use_via)
{
    logger::debug()
        << "proxy::handle_stateless_advert() proxy=" << (ifa() ? ifa()->name() : "null") << ", taddr=" << taddr.to_string() << ", ifname=" << ifname;

    ptr<session> se = find_or_create_session(taddr);
    if (!se) return;

    if (_autowire == true && se->status() == session::WAITING) {
        se->handle_auto_wire(saddr, ifname, use_via);
    }
}

void proxy::handle_solicit(const address& saddr, const address& taddr, const std::string& ifname)
{
    logger::debug()
        << "proxy::handle_solicit()";

    // Otherwise find or create a session to scan for this address
    ptr<session> se = find_or_create_session(taddr);
    if (!se) return;

    // Touching the session will cause an NDP advert to be transmitted to all
    // the daughters
    se->touch();

    // If our session is confirmed then we can respoond with an advert otherwise
    // subscribe so that if it does become active we can notify everyone
    if (saddr != taddr) {
        switch (se->status()) {
            case session::WAITING:
            case session::INVALID:
                se->add_pending(saddr);
                break;

            case session::VALID:
            case session::RENEWING:
                se->send_advert(saddr);
                break;
        }
     }
}

ptr<rule> proxy::add_rule(const address& addr, const ptr<iface>& ifa, bool autovia)
{
    ptr<rule> ru(rule::create(_ptr, addr, ifa));
    ru->autovia(autovia);
    _rules.push_back(ru);
    return ru;
}

ptr<rule> proxy::add_rule(const address& addr, bool aut)
{
    ptr<rule> ru(rule::create(_ptr, addr, aut));
    _rules.push_back(ru);
    return ru;
}

std::list<ptr<rule> >::iterator proxy::rules_begin()
{
    return _rules.begin();
}

std::list<ptr<rule> >::iterator proxy::rules_end()
{
    return _rules.end();
}

void proxy::remove_session(const ptr<session>& se)
{
    _sessions.remove(se);
}

const ptr<iface>& proxy::ifa() const
{
    return _ifa;
}

bool proxy::promiscuous() const
{
    return _promiscuous;
}

bool proxy::router() const
{
    return _router;
}

void proxy::router(bool val)
{
    _router = val;
}

bool proxy::autowire() const
{
    return _autowire;
}

void proxy::autowire(bool val)
{
    _autowire = val;
}

int proxy::retries() const
{
    return _retries;
}

void proxy::retries(int val)
{
    _retries = val;
}

bool proxy::keepalive() const
{
    return _keepalive;
}

void proxy::keepalive(bool val)
{
    _keepalive = val;
}

int proxy::ttl() const
{
    return _ttl;
}

void proxy::ttl(int val)
{
    _ttl = (val >= 0) ? val : 30000;
}

int proxy::deadtime() const
{
    return _deadtime;
}

void proxy::deadtime(int val)
{
    _deadtime = (val >= 0) ? val : 30000;
}

int proxy::timeout() const
{
    return _timeout;
}

void proxy::timeout(int val)
{
    _timeout = (val >= 0) ? val : 500;
}

NDPPD_NS_END
