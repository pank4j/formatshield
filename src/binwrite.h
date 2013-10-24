/* $Name: release1.0 $
 * $Id: binwrite.h,v 1.0 Jan 2, 2008 Pankaj Kohli $
 * Copyright (C) 2007 Centre for Security, Theory and Algorithmic Research (CSTAR), IIIT, Hyderabad, INDIA.
 * Copyright (C) Pankaj Kohli.
 *
 * This file is part of the FormatShield library.
 * FormatShield version 1.x: binary rewriting defense against format string attacks.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * For more information, 
 * visit http://www.codepwn.com
 */

#ifndef _BINWRITE_H
#define _BINWRITE_H

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <melf.h>
#include <dlfcn.h>
#include "util.h"

#define MAGIC_NUMBER 0xdeadbeef															/* Magic Number for the new section */
#define SECTION_NAME "fsprotect"															/* New section name */

#define numpagesrqd(contentsize,pgsize) ((((contentsize)%(pgsize))==0)?((contentsize)/(pgsize)):(((contentsize)/(pgsize))+1))		/* Number of pages required to hold contentsize of data */

#ifndef ELF32_ST_OTHER
	#define ELF32_ST_OTHER(v) ((v)&0x3)
#endif


extern unsigned long pagesize;

extern int dump(char *, char *, void *, int);
extern int load(char *, void **);


#endif
