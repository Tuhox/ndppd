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
#include <cstdarg>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <iostream>
#include <sstream>

#include "ndppd.h"
#include "logger.h"

NDPPD_NS_BEGIN

/*const char* log::_level_str[] =
{
    "fatal",
    "alert",
    "critical",
    "error",
    "warning",
    "notice",
    "info",
    "debug"
};*/

int logger::_max_pri = LOG_NOTICE;

bool logger::_syslog = false;

const logger::pri_name logger::_pri_names[] = {
    { "emergency",  LOG_EMERG   },
    { "alert",      LOG_ALERT   },
    { "critical",   LOG_CRIT    },
    { "error",      LOG_ERR     },
    { "warning",    LOG_WARNING },
    { "notice",     LOG_NOTICE  },
    { "info",       LOG_INFO    },
    { "debug",      LOG_DEBUG   },
    { NULL,         0           }
};

logger::logger(int pri) :
    _pri(pri), _force_log(false)
{
}

logger::logger(const logger& l) :
    _pri(l._pri), _ss(l._ss.str()), _force_log(false)
{
}

logger::~logger()
{
    flush();
}

std::string logger::format(const std::string& fmt, ...)
{
    char buf[2048];
    va_list va;
    va_start(va, fmt);
    vsnprintf(buf, sizeof(buf), fmt.c_str(), va);
    va_end(va);
    return buf;
}

std::string logger::err()
{
    char buf[2048];

#if (_POSIX_C_SOURCE >= 200112L || _XOPEN_SOURCE >= 600) && ! _GNU_SOURCE
    if (strerror_r(errno, buf, sizeof(buf))
        return "Unknown error";
    return buf;
#else
    return strerror_r(errno, buf, sizeof(buf));
#endif
}

logger logger::error()
{
    return logger(LOG_ERR);
}

logger logger::info()
{
    return logger(LOG_INFO);
}

logger logger::warning()
{
    return logger(LOG_WARNING);
}

logger logger::debug()
{
    return logger(LOG_DEBUG);
}

logger logger::notice()
{
    return logger(LOG_NOTICE);
}

logger& logger::operator<<(const std::string& str)
{
    _ss << str;
    return *this;
}

logger& logger::operator<<(int n)
{
    _ss << n;
    return *this;
}

logger& logger::operator<<(logger& (*pf)(logger& ))
{
    pf(*this);
    return *this;
}

logger& logger::endl(logger& __l)
{
    __l.flush();
    return __l;
}

logger& logger::force_log(bool b)
{
    _force_log = b;
    return *this;
}

void logger::flush()
{
    if (!_ss.rdbuf()->in_avail())
        return;

    if (!_force_log && (_pri > _max_pri))
        return;

#ifndef DISABLE_SYSLOG
    if (_syslog) {
        ::syslog(_pri, "(%s) %s", _pri_names[_pri].name, _ss.str().c_str());
        return;
    }
#endif

    std::cout << "(" << _pri_names[_pri].name << ") " << _ss.str() << std::endl;

    _ss.str("");
}

#ifndef DISABLE_SYSLOG
void logger::syslog(bool sl)
{
    if (sl == _syslog)
        return;

    if ((_syslog = sl)) {
        setlogmask(LOG_UPTO(LOG_DEBUG));
        openlog("ndppd", LOG_CONS | LOG_NDELAY | LOG_PERROR | LOG_PID, LOG_USER);
    } else {
        closelog();
    }
}

bool logger::syslog()
{
    return _syslog;
}
#endif

void logger::max_pri(int pri)
{
    _max_pri = pri;
}

int logger::verbosity()
{
    return _max_pri;
}

void logger::verbosity(int pri)
{
    if ((pri >= 0) && (pri <= 7)) {
        _max_pri = pri;
    }
}

bool logger::verbosity(const std::string& name)
{
    const char* c_name = name.c_str();

    if (!*c_name) {
        return false;
    }

    if (isdigit(*c_name)) {
        _max_pri = atoi(c_name);
        return true;
    }

    for (int i = 0; _pri_names[i].name; i++) {
        if (!strncmp(c_name, _pri_names[i].name, strlen(_pri_names[i].name))) {
            _max_pri = _pri_names[i].pri;
            return true;
        }
    }

    return false;
}

NDPPD_NS_END
