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
#include <algorithm>
#include <sstream>

#include "ndppd.h"
#include "proxy.h"
#include "iface.h"
#include "session.h"

NDPPD_NS_BEGIN

std::list<weak_ptr<session> > session::_sessions;

static address all_nodes = address("ff02::1");

void session::update_all(int elapsed_time)
{
    for (std::list<weak_ptr<session> >::iterator it = _sessions.begin();
            it != _sessions.end(); ) {
        if (!*it) {
            _sessions.erase(it++);
            continue;
        }

        ptr<session> se = *it++;

        if ((se->_ttl -= elapsed_time) >= 0) {
            continue;
        }

        switch (se->_status) {
            
        case session::WAITING:
            if (se->_fails < se->_retries) {
                logger::debug() << "session will keep trying [taddr=" << se->_taddr << "]";
                
                se->_ttl     = se->_pr->timeout();
                se->_fails++;
                
                // Send another solicit
                se->send_solicit();
            } else {
                
                logger::debug() << "session is now invalid [taddr=" << se->_taddr << "]";
                
                se->_status = session::INVALID;
                se->_ttl    = se->_pr->deadtime();
            }
            break;
            
        case session::RENEWING:
            logger::debug() << "session is became invalid [taddr=" << se->_taddr << "]";
            
            if (se->_fails < se->_retries) {
                se->_ttl     = se->_pr->timeout();
                se->_fails++;
                
                // Send another solicit
                se->send_solicit();
            } else {            
                se->_pr->remove_session(se);
            }
            break;
            
        case session::VALID:            
            if (se->touched() == true ||
                se->keepalive() == true)
            {
                logger::debug() << "session is renewing [taddr=" << se->_taddr << "]";
                se->_status  = session::RENEWING;
                se->_ttl     = se->_pr->timeout();
                se->_fails   = 0;
                se->_touched = false;

                // Send another solicit to make sure the route is still valid
                se->send_solicit();
            } else {
                se->_pr->remove_session(se);
            }            
            break;

        default:
            se->_pr->remove_session(se);
        }
    }
}

session::~session()
{
    logger::debug() << "session::~session() this=" << logger::format("%x", this);
    
    if (_wired == true) {
        for (std::list<ptr<iface> >::iterator it = _ifaces.begin();
            it != _ifaces.end(); it++) {
            handle_auto_unwire((*it)->name());
        }
    }
}

ptr<session> session::create(const ptr<proxy>& pr, const address& taddr, bool auto_wire, bool keepalive, int retries)
{
    ptr<session> se(new session());

    se->_ptr       = se;
    se->_pr        = pr;
    se->_taddr     = taddr;
    se->_autowire  = auto_wire;
    se->_keepalive = keepalive;
    se->_retries   = retries;
    se->_wired     = false;
    se->_ttl       = pr->ttl();
    se->_touched   = false;

    _sessions.push_back(se);

    logger::debug()
        << "session::create() pr=" << logger::format("%x", (proxy* )pr) << ", proxy=" << ((pr->ifa()) ? pr->ifa()->name() : "null")
        << ", taddr=" << taddr << " =" << logger::format("%x", (session* )se);

    return se;
}

void session::add_iface(const ptr<iface>& ifa)
{
    if (std::find(_ifaces.begin(), _ifaces.end(), ifa) != _ifaces.end())
        return;

    _ifaces.push_back(ifa);
}

void session::add_pending(const ether_addr &hwaddr, const address &addr)
{
    for (std::list<ptr<solicitor> >::iterator ad = _pending.begin(); ad != _pending.end(); ad++) {
        if ((*ad)->is(addr, hwaddr))
            return;
    }

    _pending.push_back(new solicitor(addr, hwaddr));
}

void session::send_solicit()
{
    logger::debug() << "session::send_solicit() (_ifaces.size() = " << _ifaces.size() << ")";

    for (std::list<ptr<iface> >::iterator it = _ifaces.begin();
            it != _ifaces.end(); it++) {
        logger::debug() << " - " << (*it)->name();
        (*it)->write_solicit(_taddr);
    }
}

void session::touch()
{
    if (_touched == false)
    {
        _touched = true;
        
        if (status() == session::WAITING || status() == session::INVALID) {
            _ttl = _pr->timeout();
            
            logger::debug() << "session is now probing [taddr=" << _taddr << "]";
            
            send_solicit();
        }
    }
}

void session::send_advert(const ether_addr &dhwaddr, const address& daddr)
{
    _pr->ifa()->write_advert(dhwaddr, daddr, _taddr, _pr->router());
}

void session::handle_auto_wire(const address& saddr, const std::string& ifname, bool use_via)
{
    if (_wired == true && (_wired_via.is_empty() || _wired_via == saddr))
        return;
    
    logger::debug()
        << "session::handle_auto_wire() taddr=" << _taddr << ", ifname=" << ifname;
    
    if (use_via == true &&
        _taddr != saddr &&
        saddr.is_unicast() == true &&
        saddr.is_multicast() == false)
    {
        std::stringstream route_cmd;
        route_cmd << "ip";
        route_cmd << " " << "-6";
        route_cmd << " " << "route";
        route_cmd << " " << "replace";
        route_cmd << " " << std::string(saddr);
        route_cmd << " " << "dev";
        route_cmd << " " << ifname;

        logger::debug()
            << "session::system(" << route_cmd.str() << ")";
        
        system(route_cmd.str().c_str());
        
        _wired_via = saddr;
    }
    else
        _wired_via.reset();
    
    {
        std::stringstream route_cmd;
        route_cmd << "ip";
        route_cmd << " " << "-6";
        route_cmd << " " << "route";
        route_cmd << " " << "replace";
        route_cmd << " " << std::string(_taddr);
        if (_wired_via.is_empty() == false) {
            route_cmd << " " << "via";
            route_cmd << " " << std::string(_wired_via);
        }
        route_cmd << " " << "dev";
        route_cmd << " " << ifname;

        logger::debug()
            << "session::system(" << route_cmd.str() << ")";

        system(route_cmd.str().c_str());
    }
    
    _wired = true;
}

void session::handle_auto_unwire(const std::string& ifname)
{
    logger::debug()
        << "session::handle_auto_unwire() taddr=" << _taddr << ", ifname=" << ifname;
    
    {
        std::stringstream route_cmd;
        route_cmd << "ip";
        route_cmd << " " << "-6";
        route_cmd << " " << "route";
        route_cmd << " " << "flush";
        route_cmd << " " << std::string(_taddr);
        if (_wired_via.is_empty() == false) {
            route_cmd << " " << "via";
            route_cmd << " " << std::string(_wired_via);
        }
        route_cmd << " " << "dev";
        route_cmd << " " << ifname;

        logger::debug()
            << "session::system(" << route_cmd.str() << ")";

        system(route_cmd.str().c_str());
    }
    
    if (_wired_via.is_empty() == false) {
        std::stringstream route_cmd;
        route_cmd << "ip";
        route_cmd << " " << "-6";
        route_cmd << " " << "route";
        route_cmd << " " << "flush";
        route_cmd << " " << std::string(_wired_via);
        route_cmd << " " << "dev";
        route_cmd << " " << ifname;

        logger::debug()
            << "session::system(" << route_cmd.str() << ")";

        system(route_cmd.str().c_str());
    }
    
    _wired = false;
    _wired_via.reset();
}

void session::handle_advert(const address& saddr, const std::string& ifname, bool use_via)
{
    if (_autowire == true && _status == WAITING) {
        handle_auto_wire(saddr, ifname, use_via);
    }
    
    handle_advert();
}


void session::handle_advert()
{
    logger::debug()
        << "session::handle_advert() taddr=" << _taddr << ", ttl=" << _pr->ttl();
    
    if (_status != VALID) {
        _status = VALID;
        
        logger::debug() << "session is active [taddr=" << _taddr << "]";
    }
    
    _ttl    = _pr->ttl();
    _fails  = 0;
    
    if (!_pending.empty()) {
        for (std::list<ptr<solicitor> >::iterator ad = _pending.begin();
                ad != _pending.end(); ad++) {
            ptr<solicitor> psolicitor = (*ad);
            logger::debug() << " - forward to " << *psolicitor;

            send_advert(psolicitor->hwaddr(), psolicitor->addr());
        }

        _pending.clear();
    }
}

const address& session::taddr() const
{
    return _taddr;
}

bool session::autowire() const
{
    return _autowire;
}

bool session::keepalive() const
{
    return _keepalive;
}

int session::retries() const
{
    return _retries;
}

int session::fails() const
{
    return _fails;
}

bool session::wired() const
{
    return _wired;
}

bool session::touched() const
{
    return _touched;
}

int session::status() const
{
    return _status;
}

void session::status(int val)
{
    _status = val;
}

NDPPD_NS_END
