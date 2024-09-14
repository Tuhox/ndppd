SHELL = /bin/sh

ifdef DEBUG
CXXFLAGS ?= -g -DDEBUG
else
CXXFLAGS ?= -O3
endif
# pedantic much?
CXXFLAGS += -Wall -Wextra -Werror

PREFIX  ?= /usr/local
CXX     ?= g++
GZIP    ?= /bin/gzip
MANDIR  ?= ${DESTDIR}${PREFIX}/share/man
SBINDIR ?= ${DESTDIR}${PREFIX}/sbin
PKG_CONFIG ?= pkg-config


OBJS     = src/logger.o src/ndppd.o src/iface.o src/proxy.o src/address.o \
           src/rule.o src/session.o src/conf.o src/route.o

ifdef WITH_ND_NETLINK
  LIBS     = `${PKG_CONFIG} --libs glib-2.0 libnl-3.0 libnl-route-3.0` -pthread
  CPPFLAGS = `${PKG_CONFIG} --cflags glib-2.0 libnl-3.0 libnl-route-3.0`
  OBJ      = ${OBJ} src/nd-netlink.o
endif

.PHONY: all
all: ndppd ndppd.1.gz ndppd.conf.5.gz

.PHONY: install
install: all
	mkdir -p ${SBINDIR} ${MANDIR} ${MANDIR}/man1 ${MANDIR}/man5
	cp ndppd ${SBINDIR}
	chmod +x ${SBINDIR}/ndppd
	cp ndppd.1.gz ${MANDIR}/man1
	cp ndppd.conf.5.gz ${MANDIR}/man5

ndppd.1.gz:
	${GZIP} < ndppd.1 > ndppd.1.gz

ndppd.conf.5.gz:
	${GZIP} < ndppd.conf.5 > ndppd.conf.5.gz

ndppd: ${OBJS}
	${CXX} -o ndppd ${LDFLAGS} ${OBJS} ${LIBS}

nd-proxy: nd-proxy.c
	${CXX} -o nd-proxy -Wall -Werror -Wextra -Werror ${LDFLAGS} `${PKG_CONFIG} --cflags glib-2.0` nd-proxy.c `${PKG_CONFIG} --libs glib-2.0`

.cc.o:
	${CXX} -c ${CPPFLAGS} $(CXXFLAGS) -o $@ $<

.PHONY: clean
clean:
	rm -f ndppd ndppd.conf.5.gz ndppd.1.gz ${OBJS} nd-proxy
