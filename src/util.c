/* $Name: release1.0 $
 * $Id: util.c,v 1.0 Jan 2, 2008 Pankaj Kohli $
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

#define _GNU_SOURCE

#include <stdlib.h>
#include <dlfcn.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include "util.h"


uint32_t extend = 0;												/* Number of bytes by which binary was extended towards lower addresses */
uint32_t base = 0;													/* Base address of the object extended towards lower addresses */
int _formatshield_exclude = 0;										/* Exclude current process from all checks ? */


/*
	Functions to intercept
	TODO: Intercept remaining functions
	
	As fyre said "Stop duplicating so much code!" :D
*/
int (*_printf)(const char *format, ...) = NULL;
int (*_fprintf)(FILE *stream, const char *format, ...) = NULL;
int (*_sprintf)(char *str, const char *format, ...) = NULL;
int (*_snprintf)(char *str, size_t size, const char *format, ...) = NULL;
int (*_vprintf)(const char *format, va_list ap) = NULL;
int (*_vfprintf)(FILE *stream, const char *format, va_list ap) = NULL;
int (*_vsprintf)(char *str, const char *format, va_list ap) = NULL;
int (*_vsnprintf)(char *str, size_t size, const char *format, va_list ap) = NULL;
void (*_syslog)(int priority, const char *format, ...) = NULL;
void (*_vsyslog)(int priority, const char *format, va_list ap) = NULL;


/*
	This function follows the chain of frame pointers on the stack to
	retrieve the set of stored return addresses. The set of return 
	addresses is stored in the array retaddr upto the specified maximum limit.
	Returns the number of return addresses retrieved.
*/
int _stack_backtrace(uint32_t *retaddr, int limit) {
	int num=0, i, j;
	uint32_t *fp, ret;
	
	/* Get the address of stored frame pointer of the topmost stack frame */
	__asm__ __volatile__ ("mov %%ebp, %0\n\t" : "=m"(fp));
	
	/* Loop till the limit is reached or the entire chain is traversed */
	for ( i=0; i<limit && *fp; i++ ) {
		/* Get stored return address */
		ret = *(fp+1);
		
		/* Decompose the return address */
		for ( j=0; j < basemapsize-1; j++) {
			if ( ret > basemap[j] && ret < basemap[j+1] ) {
				retaddr[i] = ret - basemap[j];
				
				if ( basemap[j] == base ) retaddr[i] = retaddr[i] - extend;
				break;
			}
		}
		
		/* Follow the chain */
		fp = (uint32_t *) *fp;
		num++;
	}

	return num;
}



/*
	By Paul Hsieh (C) 2004, 2005.  Covered under the Paul Hsieh derivative license.
	See: http://www.azillionmonkeys.com/qed/weblicense.html for license details.
	
	http://www.azillionmonkeys.com/qed/hash.html
*/
#undef get16bits
#if (defined(__GNUC__) && defined(__i386__)) || defined(__WATCOMC__) \
  || defined(_MSC_VER) || defined (__BORLANDC__) || defined (__TURBOC__)
#define get16bits(d) (*((const uint16_t *) (d)))
#endif

#if !defined (get16bits)
#define get16bits(d) ((((uint32_t)(((const uint8_t *)(d))[1])) << 8)\
                       +(uint32_t)(((const uint8_t *)(d))[0]) )
#endif

uint32_t SuperFastHash (const char *data, int len) {
	uint32_t hash = 0, tmp;
	int rem;

	if (len <= 0 || data == NULL) return 0;

	rem = len & 3;
	len >>= 2;

	/* Main loop */
	for (;len > 0; len--) {
		hash  += get16bits (data);
		tmp    = (get16bits (data+2) << 11) ^ hash;
		hash   = (hash << 16) ^ tmp;
		data  += 2*sizeof (uint16_t);
		hash  += hash >> 11;
	}

	/* Handle end cases */
	switch (rem) {
		case 3:	hash += get16bits (data);
				hash ^= hash << 16;
				hash ^= data[sizeof (uint16_t)] << 18;
				hash += hash >> 11;
				break;
		case 2:	hash += get16bits (data);
				hash ^= hash << 11;
				hash += hash >> 17;
				break;
		case 1: hash += *data;
				hash ^= hash << 10;
				hash += hash >> 1;
	}

	/* Force "avalanching" of final 127 bits */
	hash ^= hash << 3;
	hash += hash >> 5;
	hash ^= hash << 4;
	hash += hash >> 17;
	hash ^= hash << 25;
	hash += hash >> 6;

	return hash;
}



/*
	Log to syslog
*/
void _logit(int level, const char *format, ...) {
	va_list ap;
	
	if( ! _formatshield_exclude ) {
		va_start(ap, format);
		_vlogit(level, format, ap);
		va_end(ap);
	}
}

/*
	Log to syslog (variadic version)
*/
void _vlogit(int level, const char *format, va_list ap) {
	if( ! _formatshield_exclude ) {
		openlog(LIB, LOG_PID, LOG_AUTHPRIV);
		_vsyslog(level, format, ap);
		closelog();	
	}
}



/*
	Violation detected. Write a log to syslog and kill the current process.
	TODO: Dump core
*/
void _formatshield_die(const char *format, ...) {
	va_list ap;
	
	va_start(ap, format);
	
	/* Display error to stderr */
#ifdef DISPLAY_ERROR
	if ( ! _formatshield_exclude ) _vfprintf(stderr, format, ap);
#endif

	/* Log to syslog */
#ifdef LOG_TO_SYSLOG
	_vlogit(LOG_CRIT, format, ap);
#endif

	va_end(ap);
	
	/* Kill process */
	raise(SIGKILL);
}


/*
	Copy a file
*/
int copy(char *src, char *dest) {
	int inF, ouF;
  	char line[512];
  	int bytes;

  	if ( (inF = open(src, O_RDONLY)) == -1 ) {
  		return 1;
  	}

  	if ( (ouF = open(dest, O_WRONLY | O_CREAT | O_NONBLOCK)) == -1 ) {
    		return 1;
  	}

	while ( (bytes = read(inF, line, sizeof(line))) > 0 )
    		write(ouF, line, bytes);

  	close(inF);
  	close(ouF);
  	
  	return 0;
}




