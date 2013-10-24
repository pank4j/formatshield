# $Name: release1.0 $
# $Id: Makefile,v 1.0 Jan 2, 2008 Pankaj Kohli $
# Copyright (C) 2007 Centre for Security, Theory and Algorithmic Research (CSTAR), IIIT, Hyderabad, INDIA.
# Copyright (C) Pankaj Kohli.
#
# This file is part of the FormatShield library.
# FormatShield version 1.x: binary rewriting defense against format string attacks.
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public
# License as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
# For more information, 
# visit http://www.codepwn.com
#


MAJOR_VERSION	= 1
MINOR_VERSION	= 0
PATCHLEVEL		= 0

VERSION		= $(MAJOR_VERSION).$(MINOR_VERSION).$(PATCHLEVEL)

LIBNAME		= libfshield.so.$(VERSION)
LIBLINK		= libfshield.so.$(MAJOR_VERSION)
LIBDIR		= /lib
PRELOAD	= /etc/ld.so.preload

CC		= gcc
INSTALL		= install

LDFLAGS		= -shared -Wl,-soname,${LIBLINK} -ldl -lmelf
SRCS		= fshield.c util.c binwrite.c
OBJECTS		= fshield.o util.o binwrite.o
HEADERS	= util.h binwrite.h
CCFLAGS		= -O2 -Wall -fPIC
IFLAGS		= -I../lib/libmelf -I.
LPATH		= -L../lib/libmelf
DEBUG_FLAGS	= -g

all	:	$(LIBNAME)

debug	:	CCFLAGS += $(DEBUG_FLAGS)
debug	:	all

.c.o	:	
		$(CC)  $(CCFLAGS) -c $< $(IFLAGS)

${LIBNAME}:	$(OBJECTS)
			$(CC) $(LDFLAGS) $(LFLAGS) $(LPATH) $(CCFLAGS) ${OBJECTS} -o ${LIBNAME}
			ln -sf $(LIBNAME) libfshield.so

clean	:	
			rm -f *.o libfshield.so*

install	:	$(LIBNAME)
			@if [ -f $(PRELOAD) ] ; then \
			echo "Removing formatshield from $(PRELOAD) (if exists)"; \
			cp -fp $(PRELOAD) $(PRELOAD).save ; \
			grep -v formatshield $(PRELOAD) > $(PRELOAD).tmp ; \
			rm -f $(PRELOAD) ;\
			fi; \

			$(INSTALL) $(LIBNAME) $(LIBDIR) 
			/sbin/ldconfig

			@if [ -s $(PRELOAD).tmp ] ; then \
			cp -fp $(PRELOAD).tmp $(PRELOAD);\
			fi ;\
			rm -f $(PRELOAD).tmp 

			@echo -n "Type y for installing formatshield system wide?[default n] ";\
			read reply; \
			if [ "$$reply" = 'y' ] ; then \
		        if [ -f $(LIBDIR)/$(LIBLINK) ] ; then \
			echo "$(LIBDIR)/$(LIBLINK)" >> $(PRELOAD) ; \
			fi; \
			fi

uninstall	:
			echo "Uninstalling formatshield";
			rm -f $(LIBDIR)/$(LIBNAME)
			@if [ -f $(PRELOAD) ] ; then \
			echo "Removing formatshield from $(PRELOAD) (if exists)"; \
			grep -v formatshield $(PRELOAD) > $(PRELOAD).tmp ; \
			mv $(PRELOAD).tmp $(PRELOAD) ;\
			fi; \




