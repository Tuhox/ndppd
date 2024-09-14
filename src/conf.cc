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
#include <cstring>
#include <cctype>
#include <cstdlib>
#include <memory>
#include <string>
#include <iostream>
#include <fstream>
#include <netinet/ip6.h>

#include "ndppd.h"

NDPPD_NS_BEGIN

conf::conf() :
    _is_block(false)
{

}

conf::operator int() const
{
    return as_int();
}

conf::operator const std::string&() const
{
    return as_str();
}

conf::operator bool() const
{
    return as_bool();
}

bool conf::as_bool() const
{
    if (!strcasecmp(_value.c_str(), "true") || !strcasecmp(_value.c_str(), "yes"))
        return true;
    else
        return false;
}

const std::string& conf::as_str() const
{
    return _value;
}

int conf::as_int() const
{
    return atoi(_value.c_str());
}

bool conf::empty() const
{
    return _value == "";
}

ptr<conf> conf::load(const std::string& path)
{
    try {
        std::ifstream ifs;
        ifs.exceptions(std::ifstream::failbit | std::ifstream::badbit);
        ifs.open(path.c_str(), std::ios::in);
        ifs.exceptions(std::ifstream::badbit);
        std::string buf((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());

        const char* c_buf = buf.c_str();

        ptr<conf> cf(new conf);

        if (cf->parse_block(&c_buf)) {
            cf->dump(LOG_DEBUG);
            return cf;
        }

        logger::error() << "Could not parse configuration file";
    } catch (std::ifstream::failure & e) {
        logger::error() << "Failed to load configuration file '" << path << "'";
    }

    return ptr<conf>();
}

bool conf::is_block() const
{
    return _is_block;
}

const char* conf::skip(const char* str, bool newlines)
{
    while (*str) {
        while (*str && isspace(*str) && ((*str != '\n') || newlines))
            str++;

        if ((*str == '#') || ((*str == '/') && (*(str + 1) == '/'))) {
            while (*str && (*str != '\n')) {
                str++;
            }
        } else if ((*str == '/') && (*(str + 1) == '*')) {
            while (*str) {
                if ((*str == '*') && (*(str + 1) == '/')) {
                    str += 2;
                    break;
                }
                str++;
            }
        } else {
            break;
        }
    }

    return str;
}

bool conf::parse_block(const char** str)
{
    const char* p = *str;

    _is_block = true;

    while (*p) {
        std::stringstream ss;

        p = skip(p, true);

        if ((*p == '}') || !*p) {
            *str = p;
            return true;
        }

        while (isalnum(*p) || (*p == '_') || (*p == '-')) {
            ss << *p++;
        }

        p = skip(p, false);

        if (*p == '=') {
            p++;
            p = skip(p, false);
        }

        ptr<conf> cf(new conf);

        if (cf->parse(&p)) {
            _map.insert(std::pair<std::string, ptr<conf> >(ss.str(), cf));
        } else {
            return false;
        }
    }

    *str = p;
    return true;
}

bool conf::parse(const char** str)
{
    const char* p = *str;
    std::stringstream ss;

    p = skip(p, false);

    if ((*p == '\'') || (*p == '"')) {
        for (char e = *p++; *p && (*p != e) && (*p != '\n'); p++)
            ss << *p;
        p = skip(p, false);
    } else {
        while (*p && isgraph(*p) && (*p != '{') && (*p != '}')) {
            ss << *p++;
        }
    }

    _value = ss.str();

    p = skip(p, false);

    if (*p == '{') {
        p++;

        if (!parse_block(&p)) {
            return false;
        }

        if (*p != '}') {
            return false;
        }

        p++;
    }

    *str = p;
    return true;
}

void conf::dump(int pri) const
{
    logger l(pri);
    dump(l, 0);
}

void conf::dump(logger& l, int level) const
{
    std::string pfx;
    for (int i = 0; i < level; i++) {
        pfx += "    ";
    }

    if (_value != "") {
        l << _value << " ";
    }

    if (_is_block) {
        l << "{" << logger::endl;

        std::multimap<std::string, ptr<conf> >::const_iterator it;

        for (it = _map.begin(); it != _map.end(); it++) {
            l << pfx << "    " << it->first << " ";
            it->second->dump(l, level + 1);
        }

        l << pfx << "}" << logger::endl;
    }

    l << logger::endl;
}

ptr<conf> conf::operator()(const std::string& name, int index) const
{
    return find(name, index);
}

ptr<conf> conf::find(const std::string& name, int index) const
{
    std::multimap<std::string, ptr<conf> >::const_iterator it;
    for (it = _map.find(name); it != _map.end(); it++) {
        if (index-- <= 0)
            return it->second;
    }

    return ptr<conf>();
}

ptr<conf> conf::operator[](const std::string& name) const
{
    return find(name, 0);
}

std::vector<ptr<conf> > conf::find_all(const std::string& name) const
{
    std::vector<ptr<conf> > vec;

    std::multimap<std::string, ptr<conf> >::const_iterator it;

    std::pair<std::multimap<std::string, ptr<conf> >::const_iterator,
        std::multimap<std::string, ptr<conf> >::const_iterator> ret;

    ret = _map.equal_range(name);

    for (it = ret.first; it != ret.second; it++) {
        vec.push_back(it->second);
    }

    return vec;
}

conf::operator const std::string&()
{
    return _value;
}

NDPPD_NS_END
