/* $Name: release1.0 $
 * $Id: README,v 1.0 Jan 2, 2008 Pankaj Kohli $
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

FormatShield is a library that intercepts call to vulnerable functions and uses binary
rewriting to defend against format string attacks. It identifies the vulnerable call sites
 in a running process and dumps the corresponding context information in the ELF 
 binary of the process. Attacks are detected when format specifiers are found at 
 these contexts of the vulnerable call sites.

FormatShield provides wrappers for the following libc functions:

       int printf(const char *format, ...)
       int fprintf(FILE *stream, const char *format, ...)
       int sprintf(char *str, const char *format, ...)
       int snprintf(char *str, size_t size, const char *format, ...)
       int vprintf(const char *format, va_list ap)
       int vfprintf(FILE *stream, const char *format, va_list ap)
       int vsprintf(char *str, const char *format, va_list ap)
       int vsnprintf(char *str, size_t size, const char *format, va_list ap)
       void syslog(int priority, const char *format, ...)
       void vsyslog(int priority, const char *format, va_list ap)


On detecting an attack, the victim process is killed and a log is written to syslog.


