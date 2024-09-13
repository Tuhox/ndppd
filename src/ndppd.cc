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
#include <cstdlib>
#include <csignal>

#include <iostream>
#include <fstream>
#include <string>
#include <memory>

#include <getopt.h>
#include <sys/time.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "ndppd.h"
#include "route.h"

using namespace ndppd;

static int daemonize()
{
    pid_t pid = fork();
    if (pid < 0) {
        logger::error() << "Failed to fork during daemonize: " << logger::err();
        return -1;
    }

    if (pid > 0)
        exit(0);

    umask(0);

    pid_t sid = setsid();
    if (sid < 0) {
        logger::error() << "Failed to setsid during daemonize: " << logger::err();
        return -1;
    }

    if (chdir("/") < 0) {
        logger::error() << "Failed to change path during daemonize: " << logger::err();
        return -1;
    }

    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    return 0;
}

static ptr<conf> load_config(const std::string& path)
{
    ptr<conf> cf, x_cf;

    if (!(cf = conf::load(path)))
        return (conf*)NULL;

    std::vector<ptr<conf> >::const_iterator p_it;

    std::vector<ptr<conf> > proxies(cf->find_all("proxy"));

    for (p_it = proxies.begin(); p_it != proxies.end(); p_it++) {
        ptr<conf> pr_cf = *p_it;

        if (pr_cf->empty()) {
            logger::error() << "'proxy' section is missing interface name";
            return (conf*)NULL;
        }

        std::vector<ptr<conf> >::const_iterator r_it;

        std::vector<ptr<conf> > rules(pr_cf->find_all("rule"));

        for (r_it = rules.begin(); r_it != rules.end(); r_it++) {
            ptr<conf> ru_cf =* r_it;

            if (ru_cf->empty()) {
                logger::error() << "'rule' is missing an IPv6 address/net";
                return (conf*)NULL;
            }

            address addr(*ru_cf);

            if ((x_cf = ru_cf->find("iface"))) {
                if (ru_cf->find("static") || ru_cf->find("auto")) {
                    logger::error()
                        << "Only one of 'iface', 'auto' and 'static' may "
                        << "be specified.";
                    return (conf*)NULL;
                }
                if ((const std::string&)*x_cf == "") {
                    logger::error() << "'iface' expected an interface name";
                    return (conf*)NULL;
                }
            } else if (ru_cf->find("static")) {
                if (ru_cf->find("auto")) {
                    logger::error()
                        << "Only one of 'iface', 'auto' and 'static' may "
                        << "be specified.";
                    return (conf*)NULL;
                }
                if (addr.prefix() <= 120) {
                    logger::warning()
                        << "Low prefix length (" << addr.prefix()
                        << " <= 120) when using 'static' method";
                }
            } else if (!ru_cf->find("auto")) {
                logger::error()
                    << "You must specify either 'iface', 'auto' or "
                    << "'static'";
                return (conf*)NULL;

            }
        }
    }

    return cf;
}

static bool configure(ptr<conf>& cf)
{
    ptr<conf> x_cf;

    if (!(x_cf = cf->find("route-ttl")))
        route::ttl(30000);
    else
        route::ttl(*x_cf);

    if (!(x_cf = cf->find("address-ttl")))
        address::ttl(30000);
    else
        address::ttl(*x_cf);

    std::list<ptr<rule> > myrules;

    std::vector<ptr<conf> >::const_iterator p_it;

    std::vector<ptr<conf> > proxies(cf->find_all("proxy"));

    for (p_it = proxies.begin(); p_it != proxies.end(); p_it++) {
        ptr<conf> pr_cf = *p_it;

        if (pr_cf->empty()) {
            return false;
        }

        bool promiscuous = false;
        if (!(x_cf = pr_cf->find("promiscuous")))
            promiscuous = false;
        else
            promiscuous = *x_cf;

        ptr<proxy> pr = proxy::open(*pr_cf, promiscuous);
        if (!pr || pr.is_null() == true) {
            return false;
        }

        if (!(x_cf = pr_cf->find("router")))
            pr->router(true);
        else
            pr->router(*x_cf);

        if (!(x_cf = pr_cf->find("autowire")))
            pr->autowire(false);
        else
            pr->autowire(*x_cf);

        if (!(x_cf = pr_cf->find("keepalive")))
            pr->keepalive(true);
        else
            pr->keepalive(*x_cf);

        if (!(x_cf = pr_cf->find("retries")))
            pr->retries(3);
        else
            pr->retries(*x_cf);

        if (!(x_cf = pr_cf->find("ttl")))
            pr->ttl(30000);
        else
            pr->ttl(*x_cf);

        if (!(x_cf = pr_cf->find("deadtime")))
            pr->deadtime(pr->ttl());
        else
            pr->deadtime(*x_cf);

        if (!(x_cf = pr_cf->find("timeout")))
            pr->timeout(500);
        else
            pr->timeout(*x_cf);

        std::vector<ptr<conf> >::const_iterator r_it;

        std::vector<ptr<conf> > rules(pr_cf->find_all("rule"));

        for (r_it = rules.begin(); r_it != rules.end(); r_it++) {
            ptr<conf> ru_cf =* r_it;

            address addr(*ru_cf);

            bool autovia = false;
            if (!(x_cf = ru_cf->find("autovia")))
                autovia = false;
            else
                autovia = *x_cf;

            if ((x_cf = ru_cf->find("iface")))
            {
                ptr<iface> ifa = iface::open_ifd(*x_cf);
                if (!ifa || ifa.is_null() == true) {
                    return false;
                }

                ifa->add_parent(pr);

                myrules.push_back(pr->add_rule(addr, ifa, autovia));
            } else if (ru_cf->find("auto")) {
                myrules.push_back(pr->add_rule(addr, true));
            } else {
                myrules.push_back(pr->add_rule(addr, false));
            }
        }
    }

    // Print out all the topology
    for (std::map<std::string, weak_ptr<iface> >::iterator i_it = iface::_map.begin(); i_it != iface::_map.end(); i_it++) {
        ptr<iface> ifa = i_it->second;

        logger::debug() << "iface " << ifa->name() << " {";

        for (std::list<weak_ptr<proxy> >::iterator pit = ifa->serves_begin(); pit != ifa->serves_end(); pit++) {
            ptr<proxy> pr = (*pit);
            if (!pr) continue;

            logger::debug() << "  " << "proxy " << logger::format("%x", pr.get_pointer()) << " {";

             for (std::list<ptr<rule> >::iterator rit = pr->rules_begin(); rit != pr->rules_end(); rit++) {
                ptr<rule> ru = *rit;

                logger::debug() << "    " << "rule " << logger::format("%x", ru.get_pointer()) << " {";
                logger::debug() << "      " << "taddr " << ru->addr()<< ";";
                if (ru->is_auto())
                    logger::debug() << "      " << "auto;";
                else if (!ru->daughter())
                    logger::debug() << "      " << "static;";
                else
                    logger::debug() << "      " << "iface " << ru->daughter()->name() << ";";
                logger::debug() << "    }";
             }

            logger::debug() << "  }";
        }

        logger::debug() << "  " << "parents {";
        for (std::list<weak_ptr<proxy> >::iterator pit = ifa->parents_begin(); pit != ifa->parents_end(); pit++) {
            ptr<proxy> pr = (*pit);

            logger::debug() << "    " << "parent " << logger::format("%x", pr.get_pointer()) << ";";
        }
        logger::debug() << "  }";

        logger::debug() << "}";
    }

    return true;
}

static bool running = true;

static void exit_ndppd(int sig)
{
    (void)sig;
    logger::error() << "Shutting down...";
    running = 0;
}

int main(int argc, char* argv[], char* env[])
{
    (void)env;
    signal(SIGINT, exit_ndppd);
    signal(SIGTERM, exit_ndppd);

    std::string config_path("/etc/ndppd.conf");
    std::string pidfile;
    std::string verbosity;
    bool daemon = false;

    while (1) {
        int c, opt;

        static struct option long_options[] =
        {
            { "config",     1, 0, 'c' },
            { "daemon",     0, 0, 'd' },
            { "verbose",    1, 0, 'v' },
            { 0, 0, 0, 0}
        };

        c = getopt_long(argc, argv, "c:dp:v", long_options,& opt);

        if (c == -1)
            break;

        switch (c) {
        case 'c':
            config_path = optarg;
            break;

        case 'd':
            daemon = true;
            break;

        case 'p':
            pidfile = optarg;
            break;

        case 'v':
            logger::verbosity(logger::verbosity() + 1);
            /*if (optarg) {
                if (!logger::verbosity(optarg))
                    logger::error() << "Unknown verbosity level '" << optarg << "'";
            } else {
                logger::max_pri(LOG_INFO);
            }*/
            break;
        }
    }

    logger::notice()
        << "ndppd (NDP Proxy Daemon) version " NDPPD_VERSION << logger::endl
        << "Using configuration file '" << config_path << "'";

    // Load configuration.

    ptr<conf> cf = load_config(config_path);
    if (cf.is_null())
        return -1;

    if (daemon) {
        logger::syslog(true);

        if (daemonize() < 0)
            return 1;
    }

    if (!configure(cf))
        return -1;

    if (!pidfile.empty()) {
        std::ofstream pf;
        pf.open(pidfile.c_str(), std::ios::out | std::ios::trunc);
        pf << getpid() << std::endl;
        pf.close();
    }

    // Time stuff.

    struct timeval t1, t2;

    gettimeofday(&t1, 0);

#ifdef WITH_ND_NETLINK
    netlink_setup();
#endif

    while (running) {
        if (iface::poll_all() < 0) {
            if (running) {
                logger::error() << "iface::poll_all() failed";
            }
            break;
        }

        int elapsed_time;
        gettimeofday(&t2, 0);

        elapsed_time =
            ((t2.tv_sec  - t1.tv_sec)*   1000) +
            ((t2.tv_usec - t1.tv_usec) / 1000);

        t1.tv_sec  = t2.tv_sec;
        t1.tv_usec = t2.tv_usec;

        if (rule::any_auto())
            route::update(elapsed_time);

        if (rule::any_iface())
            address::update(elapsed_time);

        session::update_all(elapsed_time);
    }

#ifdef WITH_ND_NETLINK
    netlink_teardown();
#endif

    logger::notice() << "Bye";

    return 0;
}
