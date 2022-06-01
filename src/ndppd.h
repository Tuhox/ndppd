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

#include <netinet/ip6.h>
#include <memory>

#define NDPPD_NS_BEGIN   namespace ndppd {
#define NDPPD_NS_END     }

#define NDPPD_VERSION   "0.2.6"

#include <assert.h>

#include "ptr.h"

#include "logger.h"
#include "conf.h"
#include "address.h"

#include "iface.h"
#include "proxy.h"
#include "session.h"
#include "rule.h"
#include "nd-netlink.h"
