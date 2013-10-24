/* $Name: release1.0 $
 * $Id: util.h,v 1.0 Jan 2, 2008 Pankaj Kohli $
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

#ifndef _UTIL_H
#define _UTIL_H

#include <stdio.h>
#include <stdint.h>
#include <syslog.h>
#include <stdarg.h>

#define MAXMAPSIZE 256
#define BACKTRACE_LIMIT 20
#define MAXPROFILESIZE 256

#define LIB "formatshield"

#define DISPLAY_ERROR												/* Display error */
#define LOG_TO_SYSLOG												/* Log errors to syslog */

extern uint32_t extend, base;
extern uint32_t basemap[], basemapsize;
extern int _formatshield_exclude;
extern int (*_printf)(const char *format, ...);
extern int (*_fprintf)(FILE *stream, const char *format, ...);
extern int (*_sprintf)(char *str, const char *format, ...);
extern int (*_snprintf)(char *str, size_t size, const char *format, ...);
extern int (*_vprintf)(const char *format, va_list ap);
extern int (*_vfprintf)(FILE *stream, const char *format, va_list ap);
extern int (*_vsprintf)(char *str, const char *format, va_list ap);
extern int (*_vsnprintf)(char *str, size_t size, const char *format, va_list ap);
extern void (*_syslog)(int priority, const char *format, ...);
extern void (*_vsyslog)(int priority, const char *format, va_list ap);


extern void _logit(int level, const char *format, ...);
extern void _vlogit(int level, const char *format, va_list ap);
extern int _stack_backtrace(uint32_t *retaddr, int limit);
extern uint32_t SuperFastHash (const char *data, int len);
extern void _formatshield_die(const char *format, ...);
extern int copy(char *src, char *dest);

#endif

