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



DOC		= doc
SRC			= src
LIB			= lib/libmelf

all	:		formatshield doc
			
formatshield::	lib
			cd $(SRC); make

debug	::
			cd $(SRC); make debug
			make doc

doc	::
			cd $(DOC); make

clean	:
			(cd $(SRC) && make clean)
			(cd $(DOC) && make clean)
			
install	:
			(cd $(SRC) && make install)
			(cd $(DOC) && make install)

uninstall	:
			(cd $(SRC) && make uninstall)
			(cd $(DOC) && make uninstall)


