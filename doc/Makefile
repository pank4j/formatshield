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


MANNAME	= formatshield.8
MANDIR		= /usr/man/man8

INSTALL		= install

all	:		$(MANNAME).html

$(MANNAME).html	:
			groff -Thtml -mandoc $(MANNAME) > $(MANNAME).html

clean	:	
			rm -f $(MANNAME).html
			

# If you have man pages in some other directory add it here.
install	:	$(MANNAME).html
			@if [  -d $(MANDIR) ];  then \
		 	echo "$(INSTALL) $(MANNAME) $(MANDIR)"; \
		 	$(INSTALL) $(MANNAME) $(MANDIR); \
			elif [  -d /usr/share/man/man8 ];  then \
		  	echo "$(INSTALL) $(MANNAME) /usr/share/man/man8"; \
		  	$(INSTALL) $(MANNAME) /usr/share/man/man8; \
			else echo "Error: Cannot find man directories"; \
			fi

uninstall	:	
			@if [  -d $(MANDIR) ];  then \
		 	echo "rm -f $(MANDIR)/$(MANNAME)"; \
		 	rm -f $(MANDIR)/$(MANNAME); \
			elif [  -d /usr/share/man/man8 ];  then \
		  	echo "rm -f /usr/share/man/man8/$(MANNAME)"; \
		  	rm -f /usr/share/man/man8/$(MANNAME); \
			else echo "Error: Cannot find man directories"; \
			fi


