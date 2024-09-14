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
#include <vector>
#include <map>

#include <sys/poll.h>
#include <net/ethernet.h>

#include "ndppd.h"

NDPPD_NS_BEGIN

class session;
class proxy;

class iface {
public:

    // Destructor.
    ~iface();

    static ptr<iface> open_ifd(const std::string& name);

    static ptr<iface> open_pfd(const std::string& name, bool promiscuous);

    static int poll_all();

    ssize_t read(int fd, struct sockaddr* saddr, ssize_t saddr_size, uint8_t* msg, size_t size);

    ssize_t write(int fd, const address& daddr, const uint8_t* msg, size_t size);

    // Writes a NB_NEIGHBOR_SOLICIT message to the _ifd socket.
    ssize_t write_solicit(const address& taddr);

    // Writes a NB_NEIGHBOR_ADVERT message to the _ifd socket;
    ssize_t write_advert(const address& daddr, const address& taddr, bool router);

    // Reads a NB_NEIGHBOR_SOLICIT message from the _pfd socket.
    ssize_t read_solicit(address& saddr, address& daddr, address& taddr);

    // Reads a NB_NEIGHBOR_ADVERT message from the _ifd socket;
    ssize_t read_advert(address& saddr, address& taddr);

    bool handle_local(const address& saddr, const address& taddr);

    bool is_local(const address& addr);

    void handle_reverse_advert(const address& saddr, const std::string& ifname);

    // Returns the name of the interface.
    const std::string& name() const;

    std::list<weak_ptr<proxy> >::iterator serves_begin();

    std::list<weak_ptr<proxy> >::iterator serves_end();

    void add_serves(const ptr<proxy>& proxy);

    std::list<weak_ptr<proxy> >::iterator parents_begin();

    std::list<weak_ptr<proxy> >::iterator parents_end();

    void add_parent(const ptr<proxy>& parent);

    static std::map<std::string, weak_ptr<iface> > _map;

private:

    static bool _map_dirty;

    // An array of objects used with ::poll.
    static std::vector<struct pollfd> _pollfds;

    // Updates the array above.
    static void fixup_pollfds();

    static void cleanup();

    // Weak pointer so this object can reference itself.
    weak_ptr<iface> _ptr;

    // The "generic" ICMPv6 socket for reading/writing NB_NEIGHBOR_ADVERT
    // messages as well as writing NB_NEIGHBOR_SOLICIT messages.
    int _ifd;

    // This is the PF_PACKET socket we use in order to read
    // NB_NEIGHBOR_SOLICIT messages.
    int _pfd;

    // Previous state of ALLMULTI for the interface.
    int _prev_allmulti;

    // Previous state of PROMISC for the interface
    int _prev_promiscuous;

    // Name of this interface.
    std::string _name;

    std::list<weak_ptr<proxy> > _serves;

    std::list<weak_ptr<proxy> > _parents;

    // The link-layer address of this interface.
    struct ether_addr hwaddr;

    // Turns on/off ALLMULTI for this interface - returns the previous state
    // or -1 if there was an error.
    int allmulti(int state);

    // Turns on/off PROMISC for this interface - returns the previous state
    // or -1 if there was an error
    int promiscuous(int state);

    // Constructor.
    iface();
};

NDPPD_NS_END
