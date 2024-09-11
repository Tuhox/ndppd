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
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstddef>

#include <unistd.h>

#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/ether.h>
#include <netpacket/packet.h>

#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/poll.h>

#include <linux/filter.h>

#include <errno.h>
#include <string>
#include <vector>
#include <map>

#include "ndppd.h"
#include "route.h"

NDPPD_NS_BEGIN

std::map<std::string, weak_ptr<iface> > iface::_map;

bool iface::_map_dirty = false;

std::vector<struct pollfd> iface::_pollfds;

iface::iface() :
    _ifd(-1), _pfd(-1), _name("")
{
}

iface::~iface()
{
    logger::debug() << "iface::~iface()";

    if (_ifd >= 0)
        close(_ifd);

    if (_pfd >= 0) {
        if (_prev_allmulti >= 0) {
            allmulti(_prev_allmulti);
        }
        if (_prev_promiscuous >= 0) {
            promiscuous(_prev_promiscuous);
        }
        close(_pfd);
    }

    _map_dirty = true;

    _serves.clear();
    _parents.clear();
}

ptr<iface> iface::open_pfd(const std::string& name, bool promiscuous)
{
    int fd = 0;

    std::map<std::string, weak_ptr<iface> >::iterator it = _map.find(name);

    ptr<iface> ifa;

    if (it != _map.end()) {
        if (it->second->_pfd >= 0)
            return it->second;

        ifa = it->second;
    } else {
        // We need an _ifs, so let's set one up.
        ifa = open_ifd(name);
    }

    if (!ifa)
        return ptr<iface>();

    // Create a socket.

    if ((fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IPV6))) < 0) {
        logger::error() << "Unable to create socket";
        return ptr<iface>();
    }

    // Bind to the specified interface.

    struct sockaddr_ll lladdr;

    memset(&lladdr, 0, sizeof(struct sockaddr_ll));
    lladdr.sll_family   = AF_PACKET;
    lladdr.sll_protocol = htons(ETH_P_IPV6);

    if (!(lladdr.sll_ifindex = if_nametoindex(name.c_str()))) {
        close(fd);
        logger::error() << "Failed to bind to interface '" << name << "'";
        return ptr<iface>();
    }

    if (bind(fd, (struct sockaddr* )&lladdr, sizeof(struct sockaddr_ll)) < 0) {
        close(fd);
        logger::error() << "Failed to bind to interface '" << name << "'";
        return ptr<iface>();
    }

    // Switch to non-blocking mode.

    int on = 1;

    if (ioctl(fd, FIONBIO, (char* )&on) < 0) {
        close(fd);
        logger::error() << "Failed to switch to non-blocking on interface '" << name << "'";
        return ptr<iface>();
    }

    // Set up filter.

    static struct sock_filter filter[] = {
        // Load the ether_type.
        BPF_STMT(BPF_LD | BPF_H | BPF_ABS,
            offsetof(struct ether_header, ether_type)),
        // Bail if it's* not* ETHERTYPE_IPV6.
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ETHERTYPE_IPV6, 0, 5),
        // Load the next header type.
        BPF_STMT(BPF_LD | BPF_B | BPF_ABS,
            sizeof(struct ether_header) + offsetof(struct ip6_hdr, ip6_nxt)),
        // Bail if it's* not* IPPROTO_ICMPV6.
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_ICMPV6, 0, 3),
        // Load the ICMPv6 type.
        BPF_STMT(BPF_LD | BPF_B | BPF_ABS,
            sizeof(struct ether_header) + sizeof(ip6_hdr) + offsetof(struct icmp6_hdr, icmp6_type)),
        // Bail if it's* not* ND_NEIGHBOR_SOLICIT.
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ND_NEIGHBOR_SOLICIT, 0, 1),
        // Keep packet.
        BPF_STMT(BPF_RET | BPF_K, (u_int32_t)-1),
        // Drop packet.
        BPF_STMT(BPF_RET | BPF_K, 0)
    };

    static struct sock_fprog fprog = {
        8,
        filter
    };

    if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &fprog, sizeof(fprog)) < 0) {
        logger::error() << "Failed to set filter";
        return ptr<iface>();
    }

    // Set up an instance of 'iface'.

    ifa->_pfd = fd;

    // Eh. Allmulti.
    ifa->_prev_allmulti = ifa->allmulti(1);

    // Eh. Promiscuous
    if (promiscuous == true) {
        ifa->_prev_promiscuous = ifa->promiscuous(1);
    } else {
        ifa->_prev_promiscuous = -1;
    }

    _map_dirty = true;

    return ifa;
}

ptr<iface> iface::open_ifd(const std::string& name)
{
    int fd;

    std::map<std::string, weak_ptr<iface> >::iterator it = _map.find(name);

    if ((it != _map.end()) && it->second->_ifd)
        return it->second;

    // Create a socket.

    if ((fd = socket(PF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) < 0) {
        logger::error() << "Unable to create socket";
        return ptr<iface>();
    }

    // Bind to the specified interface.

    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, name.c_str(), IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,& ifr, sizeof(ifr)) < 0) {
        close(fd);
        logger::error() << "Failed to bind to interface '" << name << "'";
        return ptr<iface>();
    }

    // Detect the link-layer address.

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, name.c_str(), IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    if (ioctl(fd, SIOCGIFHWADDR,& ifr) < 0) {
        close(fd);
        logger::error()
            << "Failed to detect link-layer address for interface '"
            << name << "'";
        return ptr<iface>();
    }

    logger::debug()
        << "fd=" << fd << ", hwaddr="
        << ether_ntoa((const struct ether_addr* )&ifr.ifr_hwaddr.sa_data);

    // Set max hops.

    int hops = 255;

    if (setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hops,
                   sizeof(hops)) < 0) {
        close(fd);
        logger::error() << "iface::open_ifd() failed IPV6_MULTICAST_HOPS";
        return ptr<iface>();
    }

    if (setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &hops,
                   sizeof(hops)) < 0) {
        close(fd);
        logger::error() << "iface::open_ifd() failed IPV6_UNICAST_HOPS";
        return ptr<iface>();
    }

    // Switch to non-blocking mode.

    int on = 1;

    if (ioctl(fd, FIONBIO, (char*)&on) < 0) {
        close(fd);
        logger::error()
            << "Failed to switch to non-blocking on interface '"
            << name << "'";
        return ptr<iface>();
    }

    // Set up filter.

    struct icmp6_filter filter;
    ICMP6_FILTER_SETBLOCKALL(&filter);
    ICMP6_FILTER_SETPASS(ND_NEIGHBOR_ADVERT, &filter);

    if (setsockopt(fd, IPPROTO_ICMPV6, ICMP6_FILTER,& filter, sizeof(filter)) < 0) {
        logger::error() << "Failed to set filter";
        return ptr<iface>();
    }

    // Set up an instance of 'iface'.

    ptr<iface> ifa;

    if (it == _map.end()) {
        ifa = new iface();
        ifa->_name = name;
        ifa->_ptr  = ifa;

        _map[name] = ifa;
    } else {
        ifa = it->second;
    }

    ifa->_ifd = fd;

    memcpy(&ifa->hwaddr, ifr.ifr_hwaddr.sa_data, sizeof(struct ether_addr));

    _map_dirty = true;

    return ifa;
}

ssize_t iface::read(int fd, struct sockaddr* saddr, ssize_t saddr_size, uint8_t* msg, size_t size)
{
    struct msghdr mhdr;
    struct iovec iov;
    ssize_t len;

    if (!msg)
        return -1;

    iov.iov_len = size;
    iov.iov_base = (caddr_t)msg;

    memset(&mhdr, 0, sizeof(mhdr));
    mhdr.msg_name = (caddr_t)saddr;
    mhdr.msg_namelen = saddr_size;
    mhdr.msg_iov =& iov;
    mhdr.msg_iovlen = 1;

    if ((len = recvmsg(fd,& mhdr, 0)) < 0)
    {
        logger::error() << "iface::read() failed! error=" << logger::err() << ", ifa=" << name();
        return -1;
    }

    logger::debug() << "iface::read() ifa=" << name() << ", len=" << len;

    if (len < static_cast<ssize_t>(sizeof(struct icmp6_hdr)))
        return -1;

    return len;
}

ssize_t iface::write(int fd, const address& daddr, const uint8_t* msg, size_t size)
{
    struct sockaddr_in6 daddr_tmp;
    struct msghdr mhdr;
    struct iovec iov;

    memset(&daddr_tmp, 0, sizeof(struct sockaddr_in6));
    daddr_tmp.sin6_family = AF_INET6;
    daddr_tmp.sin6_port   = htons(IPPROTO_ICMPV6); // Needed?
    memcpy(&daddr_tmp.sin6_addr,& daddr.const_addr(), sizeof(struct in6_addr));

    iov.iov_len = size;
    iov.iov_base = (caddr_t)msg;

    memset(&mhdr, 0, sizeof(mhdr));
    mhdr.msg_name = (caddr_t)&daddr_tmp;
    mhdr.msg_namelen = sizeof(sockaddr_in6);
    mhdr.msg_iov =& iov;
    mhdr.msg_iovlen = 1;

    logger::debug() << "iface::write() ifa=" << name() << ", daddr=" << daddr.to_string() << ", len="
                    << size;

    int len;

    if ((len = sendmsg(fd,& mhdr, 0)) < 0)
    {
        logger::error() << "iface::write() failed! error=" << logger::err() << ", ifa=" << name() << ", daddr=" << daddr.to_string();
        return -1;
    }

    return len;
}

ssize_t iface::read_solicit(address& saddr, address& daddr, address& taddr)
{
    struct sockaddr_ll t_saddr;
    uint8_t msg[256];
    ssize_t len;

    if ((len = read(_pfd, (struct sockaddr*)&t_saddr, sizeof(struct sockaddr_ll), msg, sizeof(msg))) < 0) {
        logger::warning() << "iface::read_solicit() failed: " << logger::err();
        return -1;
    }

    struct ip6_hdr* ip6h =
          (struct ip6_hdr* )(msg + ETH_HLEN);

    struct nd_neighbor_solicit*  ns =
        (struct nd_neighbor_solicit*)(msg + ETH_HLEN + sizeof(struct ip6_hdr));

    taddr = ns->nd_ns_target;
    daddr = ip6h->ip6_dst;
    saddr = ip6h->ip6_src;

    // Ignore packets sent from this machine
    if (iface::is_local(saddr) == true) {
        return 0;
    }

    logger::debug() << "iface::read_solicit() saddr=" << saddr.to_string()
                    << ", daddr=" << daddr.to_string() << ", taddr=" << taddr.to_string() << ", len=" << len;

    return len;
}

ssize_t iface::write_solicit(const address& taddr)
{
    char buf[128];

    memset(buf, 0, sizeof(buf));

    struct nd_neighbor_solicit* ns =
        (struct nd_neighbor_solicit* )&buf[0];

    struct nd_opt_hdr* opt =
        (struct nd_opt_hdr* )&buf[sizeof(struct nd_neighbor_solicit)];

    opt->nd_opt_type = ND_OPT_SOURCE_LINKADDR;
    opt->nd_opt_len  = 1;

    ns->nd_ns_type   = ND_NEIGHBOR_SOLICIT;

    memcpy(&ns->nd_ns_target,& taddr.const_addr(), sizeof(struct in6_addr));

    memcpy(buf + sizeof(struct nd_neighbor_solicit) + sizeof(struct nd_opt_hdr),
           &hwaddr, 6);

    // FIXME: Alright, I'm lazy.
    static address multicast("ff02::1:ff00:0000");

    address daddr;

    daddr = multicast;

    daddr.addr().s6_addr[13] = taddr.const_addr().s6_addr[13];
    daddr.addr().s6_addr[14] = taddr.const_addr().s6_addr[14];
    daddr.addr().s6_addr[15] = taddr.const_addr().s6_addr[15];

    logger::debug() << "iface::write_solicit() taddr=" << taddr.to_string()
                    << ", daddr=" << daddr.to_string();

    return write(_ifd, daddr, (uint8_t* )buf, sizeof(struct nd_neighbor_solicit)
                 + sizeof(struct nd_opt_hdr) + 6);
}

ssize_t iface::write_advert(const address& daddr, const address& taddr, bool router)
{
    char buf[128];

    memset(buf, 0, sizeof(buf));

    struct nd_neighbor_advert* na =
        (struct nd_neighbor_advert* )&buf[0];

    struct nd_opt_hdr* opt =
        (struct nd_opt_hdr* )&buf[sizeof(struct nd_neighbor_advert)];

    opt->nd_opt_type         = ND_OPT_TARGET_LINKADDR;
    opt->nd_opt_len          = 1;

    na->nd_na_type           = ND_NEIGHBOR_ADVERT;
    na->nd_na_flags_reserved = (daddr.is_multicast() ? 0 : ND_NA_FLAG_SOLICITED) | (router ? ND_NA_FLAG_ROUTER : 0);

    memcpy(&na->nd_na_target,& taddr.const_addr(), sizeof(struct in6_addr));

    memcpy(buf + sizeof(struct nd_neighbor_advert) + sizeof(struct nd_opt_hdr),
           &hwaddr, 6);

    logger::debug() << "iface::write_advert() daddr=" << daddr.to_string()
                    << ", taddr=" << taddr.to_string();

    return write(_ifd, daddr, (uint8_t* )buf, sizeof(struct nd_neighbor_advert) +
        sizeof(struct nd_opt_hdr) + 6);
}

ssize_t iface::read_advert(address& saddr, address& taddr)
{
    struct sockaddr_in6 t_saddr;
    uint8_t msg[256];
    ssize_t len;

    memset(&t_saddr, 0, sizeof(struct sockaddr_in6));
    t_saddr.sin6_family = AF_INET6;
    t_saddr.sin6_port   = htons(IPPROTO_ICMPV6); // Needed?

    if ((len = read(_ifd, (struct sockaddr* )&t_saddr, sizeof(struct sockaddr_in6), msg, sizeof(msg))) < 0) {
        logger::warning() << "iface::read_advert() failed: " << logger::err();
        return -1;
    }

    saddr = t_saddr.sin6_addr;

    // Ignore packets sent from this machine
    if (iface::is_local(saddr) == true) {
        return 0;
    }

    if (((struct icmp6_hdr* )msg)->icmp6_type != ND_NEIGHBOR_ADVERT)
        return -1;

    taddr = ((struct nd_neighbor_solicit* )msg)->nd_ns_target;

    logger::debug() << "iface::read_advert() saddr=" << saddr.to_string() << ", taddr=" << taddr.to_string() << ", len=" << len;

    return len;
}

bool iface::is_local(const address& addr)
{
    // Check if the address is for an interface we own that is attached to
    // one of the slave interfaces
    for (std::list<ptr<route> >::iterator ad = address::addresses_begin(); ad != address::addresses_end(); ad++)
    {
        if ((*ad)->addr() == addr)
            return true;
    }
    return false;
}

bool iface::handle_local(const address& saddr, const address& taddr)
{
    // Check if the address is for an interface we own that is attached to
    // one of the slave interfaces
    for (std::list<ptr<route> >::iterator ad = address::addresses_begin(); ad != address::addresses_end(); ad++)
    {
        if ((*ad)->addr() == taddr)
        {
            // Loop through all the serves that are using this iface to respond to NDP solicitation requests
            for (std::list<weak_ptr<proxy> >::iterator pit = serves_begin(); pit != serves_end(); pit++) {
                ptr<proxy> pr = (*pit);
                if (!pr) continue;

                for (std::list<ptr<rule> >::iterator it = pr->rules_begin(); it != pr->rules_end(); it++) {
                    ptr<rule> ru = *it;

                    if (ru->daughter() && ru->daughter()->name() == (*ad)->ifname())
                    {
                        logger::debug() << "proxy::handle_solicit() found local taddr=" << taddr;
                        write_advert(saddr, taddr, false);
                        return true;
                    }
                }
            }
        }
    }

    return false;
}

void iface::handle_reverse_advert(const address& saddr, const std::string& ifname)
{
    if (!saddr.is_unicast())
        return;

    logger::debug()
        << "proxy::handle_reverse_advert()";

    // Loop through all the parents that forward new NDP soliciation requests to this interface
    for (std::list<weak_ptr<proxy> >::iterator pit = parents_begin(); pit != parents_end(); pit++) {
        ptr<proxy> parent = (*pit);
        if (!parent || !parent->ifa()) {
            continue;
        }

        // Setup the reverse path on any proxies that are dealing
        // with the reverse direction (this helps improve connectivity and
        // latency in a full duplex setup)
        for (std::list<ptr<rule> >::iterator it = parent->rules_begin(); it != parent->rules_end(); it++) {
            ptr<rule> ru = *it;

            if (ru->addr() == saddr &&
                ru->daughter()->name() == ifname)
            {
                logger::debug() << " - generating artifical advertisement: " << ifname;
                parent->handle_stateless_advert(saddr, saddr, ifname, ru->autovia());
            }
        }
    }
}

void iface::fixup_pollfds()
{
    _pollfds.resize(_map.size()*  2);

    int i = 0;

    logger::debug() << "iface::fixup_pollfds() _map.size()=" << _map.size();

    for (std::map<std::string, weak_ptr<iface> >::iterator it = _map.begin();
            it != _map.end(); it++) {
        _pollfds[i].fd      = it->second->_ifd;
        _pollfds[i].events  = POLLIN;
        _pollfds[i].revents = 0;
        i++;

        _pollfds[i].fd      = it->second->_pfd;
        _pollfds[i].events  = POLLIN;
        _pollfds[i].revents = 0;
        i++;
    }
}

void iface::cleanup()
{
    for (std::map<std::string, weak_ptr<iface> >::iterator it = _map.begin();
            it != _map.end(); ) {
        std::map<std::string, weak_ptr<iface> >::iterator c_it = it++;
        if (!c_it->second) {
            _map.erase(c_it);
        }
    }
}

int iface::poll_all()
{
    if (_map_dirty) {
        cleanup();
        fixup_pollfds();
        _map_dirty = false;
    }

    if (_pollfds.size() == 0) {
        ::sleep(1);
        return 0;
    }

    assert(_pollfds.size() == _map.size()*  2);

    int len;

    if ((len = ::poll(&_pollfds[0], _pollfds.size(), 50)) < 0) {
        logger::error() << "Failed to poll interfaces: " << logger::err();
        return -1;
    }

    if (len == 0) {
        return 0;
    }

    std::map<std::string, weak_ptr<iface> >::iterator i_it = _map.begin();

    int i = 0;

    for (std::vector<struct pollfd>::iterator f_it = _pollfds.begin();
            f_it != _pollfds.end(); f_it++) {
        assert(i_it != _map.end());

        if (i && !(i % 2)) {
            i_it++;
        }

        bool is_pfd = i++ % 2;

        ptr<iface> ifa = i_it->second;

        if (f_it->revents & POLLERR) {
            logger::error() << "Error polling interface " << ifa->_name.c_str();
            return -1;
        }

        if (!(f_it->revents & POLLIN)) {
            continue;
        }

        address saddr, daddr, taddr;
        ssize_t size;

        if (is_pfd) {
            size = ifa->read_solicit(saddr, daddr, taddr);
            if (size < 0) {
                logger::error() << "Failed to read from interface '%s'", ifa->_name.c_str();
                continue;
            }
            if (size == 0) {
                logger::debug() << "iface::read_solicit() loopback received and ignored";
                continue;
            }

            // Process any local addresses for interfaces that we are proxying
            if (ifa->handle_local(saddr, taddr) == true) {
                continue;
            }

            // We have to handle all the parents who may be interested in
            // the reverse path towards the one who sent this solicit.
            // In fact, the parent need to know the source address in order
            // to respond to NDP Solicitations
            ifa->handle_reverse_advert(saddr, ifa->name());

            // Loop through all the proxies that are using this iface to respond to NDP solicitation requests
            bool handled = false;
            for (std::list<weak_ptr<proxy> >::iterator pit = ifa->serves_begin(); pit != ifa->serves_end(); pit++) {
                ptr<proxy> pr = (*pit);
                if (!pr) continue;

                // Process the solicitation request by relating it to other
                // interfaces or lookup up any statics routes we have configured
                handled = true;
                pr->handle_solicit(saddr, taddr, ifa->name());
            }

            // If it was not handled then write an error message
            if (handled == false) {
                logger::debug() << " - solicit was ignored";
            }

        } else {
            size = ifa->read_advert(saddr, taddr);
            if (size < 0) {
                logger::error() << "Failed to read from interface '%s'", ifa->_name.c_str();
                continue;
            }
            if (size == 0) {
                logger::debug() << "iface::read_advert() loopback received and ignored";
                continue;
            }

            // Process the NDP advert
            bool handled = false;
            for (std::list<weak_ptr<proxy> >::iterator pit = ifa->parents_begin(); pit != ifa->parents_end(); pit++) {
                ptr<proxy> pr = (*pit);
                if (!pr || !pr->ifa()) {
                    continue;
                }

                // The proxy must have a rule for this interface or it is not meant to receive
                // any notifications and thus they must be ignored
                bool autovia = false;
                bool is_relevant = false;
                for (std::list<ptr<rule> >::iterator it = pr->rules_begin(); it != pr->rules_end(); it++) {
                    ptr<rule> ru = *it;

                    if (ru->addr() == taddr &&
                        ru->daughter() &&
                        ru->daughter()->name() == ifa->name())
                    {
                        is_relevant = true;
                        autovia = ru->autovia();
                        break;
                    }
                }
                if (is_relevant == false) {
                    logger::debug() << "iface::read_advert() advert is not for " << ifa->name() << "...skipping";
                    continue;
                }

                // Process the NDP advertisement
                handled = true;
                pr->handle_advert(saddr, taddr, ifa->name(), autovia);
            }

            // If it was not handled then write an error message
            if (handled == false) {
                logger::debug() << " - advert was ignored";
            }
        }
    }

    return 0;
}

int iface::allmulti(int state)
{
    struct ifreq ifr;

    logger::debug()
        << "iface::allmulti() state="
        << state << ", _name=\"" << _name << "\"";

    state = !!state;

    memset(&ifr, 0, sizeof(ifr));

    strncpy(ifr.ifr_name, _name.c_str(), IFNAMSIZ);

    if (ioctl(_pfd, SIOCGIFFLAGS, &ifr) < 0) {
        logger::error() << "Failed to get allmulti: " << logger::err();
        return -1;
    }

    int old_state = !!(ifr.ifr_flags &IFF_ALLMULTI);

    if (state == old_state) {
        return old_state;
    }

    if (state) {
        ifr.ifr_flags |= IFF_ALLMULTI;
    } else {
        ifr.ifr_flags &= ~IFF_ALLMULTI;
    }

    if (ioctl(_pfd, SIOCSIFFLAGS, &ifr) < 0) {
        logger::error() << "Failed to set allmulti: " << logger::err();
        return -1;
    }

    return old_state;
}

int iface::promiscuous(int state)
{
    struct ifreq ifr;

    logger::debug()
        << "iface::promiscuous() state="
        << state << ", _name=\"" << _name << "\"";

    state = !!state;

    memset(&ifr, 0, sizeof(ifr));

    strncpy(ifr.ifr_name, _name.c_str(), IFNAMSIZ);

    if (ioctl(_pfd, SIOCGIFFLAGS, &ifr) < 0) {
        logger::error() << "Failed to get promiscuous: " << logger::err();
        return -1;
    }

    int old_state = !!(ifr.ifr_flags &IFF_PROMISC);

    if (state == old_state) {
        return old_state;
    }

    if (state) {
        ifr.ifr_flags |= IFF_PROMISC;
    } else {
        ifr.ifr_flags &= ~IFF_PROMISC;
    }

    if (ioctl(_pfd, SIOCSIFFLAGS, &ifr) < 0) {
        logger::error() << "Failed to set promiscuous: " << logger::err();
        return -1;
    }

    return old_state;
}

const std::string& iface::name() const
{
    return _name;
}

void iface::add_serves(const ptr<proxy>& pr)
{
    _serves.push_back(pr);
}

std::list<weak_ptr<proxy> >::iterator iface::serves_begin()
{
    return _serves.begin();
}

std::list<weak_ptr<proxy> >::iterator iface::serves_end()
{
    return _serves.end();
}

void iface::add_parent(const ptr<proxy>& pr)
{
    _parents.push_back(pr);
}

std::list<weak_ptr<proxy> >::iterator iface::parents_begin()
{
    return _parents.begin();
}

std::list<weak_ptr<proxy> >::iterator iface::parents_end()
{
    return _parents.end();
}

NDPPD_NS_END
