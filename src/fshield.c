/* $Name: release1.0 $
 * $Id: fshield.c,v 1.0 Jan 2, 2008 Pankaj Kohli $
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

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <printf.h>
#include <link.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/param.h>
#include "util.h"
#include "binwrite.h"


//#define NO_DUMP															/* Define for not dumping */
//#define LOG_DEBUG															/* Define for debugging to syslog */


char pname[MAXPATHLEN];														/* Program path */
unsigned int pid;																/* PID */
uint32_t context[MAXPROFILESIZE], contextlistsize = 0;								/* Context hash list and its size */
uint32_t writemaplow[MAXMAPSIZE], writemaphigh[MAXMAPSIZE], writemapsize=0;			/* Writable address ranges */
uint32_t basemap[MAXMAPSIZE], basemapsize=0;									/* Base addresses of the current process and other loaded shared objects */


/*
	Searches the address map of the process to check if the given
	address p is writable. Returns 0 if p is nonwritable, non-zero otherwise.
*/
int iswritable(uint32_t p) {
	int i;
	
	for ( i=0; i < writemapsize; i++ ) {
		if ( (p >= writemaplow[i]) && (p < writemaphigh[i]) ) return 1;
	}
	
	return 0;
}


/*
	Searches for a given hash in the context hash list.
	Returns non-zero if hash is found, 0 otherwise.
	Note: Context hash list is sorted
*/
uint32_t getcontext(uint32_t hash) {
	int low=0, high=contextlistsize-1, mid;
	
	while ( high >= low ) {
		mid = (low + high) / 2;
		if ( context[mid] == hash ) return 1;
		else if ( hash < context[mid] ) high = mid-1;
		else low = mid + 1;
	}
	
	return 0;
}


/*
	Insert a hash in the context hash list
*/
void setcontext(uint32_t hash, uint32_t val) {
	int low=0, high=contextlistsize-1, mid=0, flag=0;

	while ( low <= high ) {
		mid = (low + high) / 2;
		if ( hash == context[mid] ) {
			context[mid] = val;
			flag = 1;
			break;
		}
		else if ( hash < context[mid] ) high = mid - 1;
		else low = mid + 1;
	}

	if ( !flag ) {
		for ( mid=contextlistsize; mid > low; mid-- ) {
			context[mid] = context[mid-1];
		}
		context[low] = hash;
		contextlistsize++;
	}
}



/*
	Intercepted functions
*/
int printf(const char *format, ...) {
	va_list ap;
	uint32_t rethash;
	int str_l=0, count=0, num, argtypes[1];
	uint32_t ret[BACKTRACE_LIMIT];
	size_t n = 1;

	/* Do not check if exclude flag is set or format string is not writable */
	if ( _formatshield_exclude || iswritable((uint32_t) format) ) {
		va_start(ap, format);
		str_l = _vprintf(format, ap);
		va_end(ap);
		return str_l;
	}

	/* Get set of stored (decomposed) return addresses */
	num = _stack_backtrace(ret, BACKTRACE_LIMIT);
	
	/* Create hash */
	rethash = SuperFastHash((char *) ret, num*4);
	
	/* Format specifiers present ? */
	count = parse_printf_format(format, n, argtypes);
	
	/* Is this context present in the context list ? */
	num = getcontext(rethash);

	if ( count > 0) {
		/* Format string contains format specifiers */
		
		if ( num == 0 ) {
			/* Context not found (safe) */
			
			va_start(ap, format);
			str_l = _vprintf(format, ap);
			va_end(ap);
			
		} else {
			/* Context found, attack detected */					
			_formatshield_die("Attack detected in %s. Sending current process the KILL signal.\n", pname);
		}
	} else {
		/* Format specifiers not found, probably a legitimate user input */
		if ( num == 0 ) {
			/* Context not found, insert it*/
			setcontext(rethash, count);
		}
		
		/* Call the equivalent function in libc */
		va_start(ap, format);
		str_l = _vprintf(format, ap);
		va_end(ap);
	}

	return str_l;	
}



int fprintf(FILE *stream, const char *format, ...) {
	va_list ap;
	uint32_t rethash;
	int str_l=0, count, num, argtypes[1];
	uint32_t ret[BACKTRACE_LIMIT];
	size_t n = 1;

	if ( _formatshield_exclude || iswritable((uint32_t) format) ) {
		va_start(ap, format);
		str_l = _vfprintf(stream, format, ap);
		va_end(ap);
		return str_l;
	}

	num = _stack_backtrace(ret, BACKTRACE_LIMIT);
	rethash = SuperFastHash((const char *) ret, num);
	count = parse_printf_format(format, n, argtypes);
	num = getcontext(rethash);

	if ( count > 0 ) {
		if ( num == 0 ) {
			va_start(ap, format);
			str_l = _vfprintf(stream, format, ap);
			va_end(ap);
			return str_l;
		} else {
			_formatshield_die("Attack detected in %s. Sending current process the KILL signal.\n", pname);
		}
	} else {
		if ( num == 0) {
			setcontext(rethash, count);
		}
		va_start(ap, format);
		str_l = _vfprintf(stream, format, ap);
		va_end(ap);
	}

	return str_l;
}



int sprintf(char *str, const char *format, ...) {
	va_list ap;
	uint32_t rethash;
	int str_l=0, count, num, argtypes[1];
	uint32_t ret[BACKTRACE_LIMIT];
	size_t n = 1;

	if ( _formatshield_exclude || iswritable((uint32_t) format) ) {
		va_start(ap, format);
		str_l = _vsprintf(str, format, ap);
		va_end(ap);
		return str_l;
	}
	
	num = _stack_backtrace(ret, BACKTRACE_LIMIT);
	rethash = SuperFastHash((const char *) ret, num);
	count = parse_printf_format(format, n, argtypes);
	num = getcontext(rethash);

	if ( count > 0 ) {
		if ( num == 0 ) {
			va_start(ap, format);
			str_l = _vsprintf(str, format, ap);
			va_end(ap);
			return str_l;
		} else {
			_formatshield_die("Attack detected in %s. Sending current process the KILL signal.\n", pname);
		}
	} else {
		if ( num == 0 ) {
			setcontext(rethash, count);
		}
		va_start(ap, format);
		str_l = _vsprintf(str, format, ap);
		va_end(ap);
	}

	return str_l;	
}




int snprintf(char *str, size_t size, const char *format, ...) {
	va_list ap;
	uint32_t rethash;
	int str_l=0, count, num, argtypes[1];
	uint32_t ret[BACKTRACE_LIMIT];
	size_t n = 1;

	if ( _formatshield_exclude || iswritable((uint32_t) format) ) {
		va_start(ap, format);
		str_l = _vsnprintf(str, size, format, ap);
		va_end(ap);
		return str_l;
	}

	num = _stack_backtrace(ret, BACKTRACE_LIMIT);
	rethash = SuperFastHash((const char *) ret, num);
	count = parse_printf_format(format, n, argtypes);
	num = getcontext(rethash);

	if ( count > 0 ) {
		if ( num == 0 ) {
			va_start(ap, format);
			str_l = _vsnprintf(str, size, format, ap);
			va_end(ap);
		} else {
			_formatshield_die("Attack detected in %s. Sending current process the KILL signal.\n", pname);
		}
	} else {
		if ( num == 0 ) {
			setcontext(rethash, count);
		}
		va_start(ap, format);
		str_l = _vsnprintf(str, size, format, ap);
		va_end(ap);
	}

	return str_l;	
}




int vprintf(const char *format, va_list ap) {
	uint32_t rethash;
	int count, num, argtypes[1];
	uint32_t ret[BACKTRACE_LIMIT];
	size_t n = 1;

	if ( _formatshield_exclude || iswritable((uint32_t) format) ) {
		return _vprintf(format, ap);
	}

	num = _stack_backtrace(ret, BACKTRACE_LIMIT);
	rethash = SuperFastHash((const char *) ret, num);
	count = parse_printf_format(format, n, argtypes);
	num = getcontext(rethash);

	if ( count > 0 ) {
		if ( num == 0 ) {
			return _vprintf(format, ap);
		} else {
			_formatshield_die("Attack detected in %s. Sending current process the KILL signal.\n", pname);
		}
	} else {
		if ( num == 0 ) {
			setcontext(rethash, count);
		}
		return _vprintf(format, ap);
	}

	return -1;	
}




int vfprintf(FILE *stream, const char *format, va_list ap) {
	uint32_t rethash;
	int count, num, argtypes[1];
	uint32_t ret[BACKTRACE_LIMIT];
	size_t n = 1;

	if ( _formatshield_exclude || iswritable((uint32_t) format) ) {
		return _vfprintf(stream, format, ap);
	}

	num = _stack_backtrace(ret, BACKTRACE_LIMIT);
	rethash = SuperFastHash((const char *) ret, num);
	count = parse_printf_format(format, n, argtypes);
	num = getcontext(rethash);

	if ( count > 0 ) {
		if ( num == 0 ) {
			return _vfprintf(stream, format, ap);
		} else {
			_formatshield_die("Attack detected in %s. Sending current process the KILL signal.\n", pname);
		}
	} else {
		if ( num == 0 ) {
			setcontext(rethash, count);
		}
		return _vfprintf(stream, format, ap);
	}

	return -1;
}




int vsprintf(char *str, const char *format, va_list ap) {
	uint32_t rethash;
	int count, num, argtypes[1];
	uint32_t ret[BACKTRACE_LIMIT];
	size_t n = 1;

	if ( _formatshield_exclude || iswritable((uint32_t) format) ) {
		return _vsprintf(str, format, ap);
	}

	num = _stack_backtrace(ret, BACKTRACE_LIMIT);
	rethash = SuperFastHash((const char *) ret, num);
	count = parse_printf_format(format, n, argtypes);
	num = getcontext(rethash);

	if ( count > 0 ) {
		if ( num == 0 ) {
			return _vsprintf(str, format, ap);
		} else {
			_formatshield_die("Attack detected in %s. Sending current process the KILL signal.\n", pname);
		}
	} else {
		if ( num == 0 ) {
			setcontext(rethash, count);
		}
		return _vsprintf(str, format, ap);
	}

	return -1;
}



int vsnprintf(char *str, size_t size, const char *format, va_list ap) {
	uint32_t rethash;
	int count, num, argtypes[1];
	uint32_t ret[BACKTRACE_LIMIT];
	size_t n = 1;

	if ( _formatshield_exclude || iswritable((uint32_t) format) ) {
		return _vsnprintf(str, size, format, ap);
	}

	num = _stack_backtrace(ret, BACKTRACE_LIMIT);
	rethash = SuperFastHash((const char *) ret, num);
	count = parse_printf_format(format, n, argtypes);
	num = getcontext(rethash);

	if ( count > 0 ) {
		if ( num == 0 ) {
			return _vsnprintf(str, size, format, ap);
		} else {
			_formatshield_die("Attack detected in %s. Sending current process the KILL signal.\n", pname);
		}
	} else {
		if ( num == 0 ) {
			setcontext(rethash, count);
		}
		return _vsnprintf(str, size, format, ap);
	}

	return -1;
}





void syslog(int priority, const char *format, ...) {
	va_list ap;
	uint32_t rethash;
	int count, num, argtypes[1];
	uint32_t ret[BACKTRACE_LIMIT];
	size_t n = 1;

	if ( _formatshield_exclude || iswritable((uint32_t) format) ) {
		va_start(ap, format);
		_vsyslog(priority, format, ap);
		va_end(ap);
		return;
	}

	num = _stack_backtrace(ret, BACKTRACE_LIMIT);
	rethash = SuperFastHash((const char *) ret, num);
	count = parse_printf_format(format, n, argtypes);
	num = getcontext(rethash);

	if ( count > 0) {
		if ( num == 0 ) {
			va_start(ap, format);
			_vsyslog(priority, format, ap);
			va_end(ap);
			return;
		} else {
			_formatshield_die("Attack detected in %s. Sending current process the KILL signal.\n", pname);
		}
	} else {
		if ( num == 0 ) {
			setcontext(rethash, count);
		}
		va_start(ap, format);
		_vsyslog(priority, format, ap);
		va_end(ap);
	}
}



void vsyslog(int priority, const char *format, va_list ap) {
	uint32_t rethash;
	int count, num, argtypes[1];
	uint32_t ret[BACKTRACE_LIMIT];
	size_t n = 1;

	if ( _formatshield_exclude || iswritable((uint32_t) format) ) {
		_vsyslog(priority, format, ap);
		return;
	}

	num = _stack_backtrace(ret, BACKTRACE_LIMIT);
	rethash = SuperFastHash((const char *) ret, num);
	count = parse_printf_format(format, n, argtypes);
	num = getcontext(rethash);

	if ( count > 0) {
		if ( num == 0 ) {
			_vsyslog(priority, format, ap);
			return;
		} else {
			_formatshield_die("Attack detected in %s. Sending current process the KILL signal.\n", pname);
		}
	} else {
		if ( num == 0 ) {
			setcontext(rethash, count);
		}
		_vsyslog(priority, format, ap);
	}
}





/*
	Callback function to build base address map for this process and
	loaded shared objects.
*/
static int getbasemap(struct dl_phdr_info *info, size_t size, void *data)
{
	void *handle = data;
	Dl_info in;

	if(*(info->dlpi_name) == 0 && info->dlpi_phnum) {
		/* This program */
		if( (handle = dlopen(NULL, RTLD_NOW)) ) {
			if( dladdr((void *) info->dlpi_phdr[0].p_vaddr, &in) ) {
				basemap[basemapsize] = (uint32_t) in.dli_fbase;
				basemapsize++;
			}
		}
		dlclose(handle);
	} else {
		/* Shared object */
		basemap[basemapsize] = info->dlpi_addr;
		basemapsize++;
	}
	
    return 0;
}



static void __attribute__ ((constructor)) _libfshield_init(void) {
	FILE *fd;
	void *handle;
	char str[MAXPATHLEN], temp[MAXPATHLEN], prot[5];
	int i, j, k, *addr;

	//Get pid & program path
	pid = getpid();
	if ( (i = readlink("/proc/self/exe", pname, MAXPATHLEN-1)) == -1 )
		_formatshield_exclude = 1;		
	else pname[i] = '\0';

	/* Intercept vulnerable functions */
	if ( _printf == NULL ) {
		_printf = (int (*)(const char *format, ...)) dlsym(RTLD_NEXT, "printf");
		if ( _printf == NULL )  { _formatshield_exclude = 1; return; }
	} 
	if ( _fprintf == NULL ) {
		_fprintf = (int (*)(FILE *stream, const char *format, ...)) dlsym(RTLD_NEXT, "fprintf");
		if ( _fprintf == NULL ) { _formatshield_exclude = 1; return; }
	}
	if ( _sprintf == NULL ) {
		_sprintf = (int (*)(char *str, const char *format, ...)) dlsym(RTLD_NEXT, "sprintf");
		if ( _sprintf == NULL ) { _formatshield_exclude = 1; return; }
	}
	if ( _snprintf == NULL ) {
		_snprintf = (int (*)(char *str, size_t size, const char *format, ...)) dlsym(RTLD_NEXT, "snprintf");
		if ( _snprintf == NULL ) { _formatshield_exclude = 1; return; }
	}
	if ( _vprintf == NULL ) {
		_vprintf = (int (*)(const char *format, va_list ap)) dlsym(RTLD_NEXT, "vprintf");
		if ( _vprintf == NULL ) { _formatshield_exclude = 1; return; }
	}
	if ( _vfprintf == NULL ) {
		_vfprintf = (int (*)(FILE *stream, const char *format, va_list ap)) dlsym(RTLD_NEXT, "vfprintf");
		if ( _vfprintf == NULL ) { _formatshield_exclude = 1; return; }
	}
	if ( _vsprintf == NULL ) {
		_vsprintf = (int (*)(char *str, const char *format, va_list ap)) dlsym(RTLD_NEXT, "vsprintf");
		if ( _vsprintf == NULL ) { _formatshield_exclude = 1; return; }
	}
	if ( _vsnprintf == NULL ) {
		_vsnprintf = (int (*)(char *str, size_t size, const char *format, va_list ap)) dlsym(RTLD_NEXT, "vsnprintf");
		if ( _vsnprintf == NULL ) { _formatshield_exclude = 1; return; }
	}
	if ( _syslog == NULL) {
		_syslog = (void (*)(int priority, const char *format, ...)) dlsym(RTLD_NEXT, "syslog");
		if ( _syslog == NULL ) { _formatshield_exclude = 1; return; }
	}
	if ( _vsyslog == NULL) {
		_vsyslog = (void (*)(int priority, const char *format, va_list ap)) dlsym(RTLD_NEXT, "vsyslog");
		if ( _vsyslog == NULL ) { _formatshield_exclude = 1; return; }
	}

	
	pagesize = getpagesize();
	
	/* Resolve symbol and load context hash list */
	if ( (handle = dlopen(NULL, RTLD_NOW)) ) {
		if ( (addr = dlsym(handle, SECTION_NAME)) ) {
			if ( (*addr == MAGIC_NUMBER) && ((extend = *(addr+1)) > 0) && (base = *(addr+2)) && ((contextlistsize = *(addr+3)) > 0) ) {
				extend *= pagesize;
				addr += 4;
				contextlistsize /= 4;												/* sizeof(hash) = 4 */
				for ( i=0; i < contextlistsize; i++ ) {
					context[i] = *(addr+i);
				}
			}
		}
		
		/* Build base address map for current process and other loaded shared objects */
		dl_iterate_phdr(getbasemap, handle);
		
		/* Sort */
		for ( i=0; i < basemapsize; i++ ) {
			for ( j=0; j < basemapsize-1; j++ ) {
				if ( basemap[j] > basemap[j+1] ) {
					k = basemap[j];
					basemap[j]  = basemap[j+1];
					basemap[j+1] = k;
				}
			}
		}
		
		/* Terminate with 0xffffffff */
		basemap[basemapsize] = 0xffffffff;
		basemapsize++;
		dlclose(handle);
	}
	
	/* Get writable address ranges for this process */
	if  ( (fd = fopen("/proc/self/maps", "r")) ) {
		i = 0;
		while ( fgets(str, MAXPATHLEN-1, fd) ) {
			sscanf(str, "%x-%x %s %s", &writemaplow[writemapsize], &writemaphigh[writemapsize], prot, temp);
			if(prot[1] == '-') writemapsize++;
		}
		fclose(fd);
	} else _formatshield_exclude = 1;

#ifdef LOG_DEBUG
	if ( !_formatshield_exclude ) _logit(LOG_INFO, "%s loaded for %s", LIB, pname);
#endif

}



static void __attribute__ ((destructor)) _libfshield_fini(void) {
	char tmp[16] = "/tmp/tmpXXXXXX";
	struct stat s;
	
	if ( !_formatshield_exclude ) {						/* Save context list*/

#ifndef NO_DUMP										/* Define NO_DUMP for not dumping (for testing) */
		if ( mkstemp(tmp) == -1 ) {

#ifdef DISPLAY_ERROR
			_fprintf(stderr, "Error creating temp file\n");
#endif

#ifdef LOG_DEBUG
			_logit(LOG_INFO, "Error creating temp file\n");
#endif

		} else {
			
			/*
				Dumping into the binary of the executing process fails.
				So, the elf is first dumped into a temporary file, the elf binray of
				the process is then deleted, and the temporary file is copied to
				its place.
			*/		
			if(dump(pname, tmp, context, contextlistsize*4) == 0) {
				stat(pname, &s);
				unlink(pname);
				copy(tmp, pname);
				chown(pname, s.st_uid, s.st_gid);
				chmod(pname, s.st_mode);
				unlink(tmp);
#ifdef DEBUG
				_fprintf(stderr, "Dumped %d bytes into %s\n", contextlistsize*4, pname);
#endif			
			} else {

#ifdef DISPLAY_ERROR
				_fprintf(stderr, "Error dumping in %s\n", pname);
#endif

#ifdef DEBUG
				_logit(LOG_INFO, "Error dumping in %s\n", pname);
#endif

			}
		}
#endif
		
#ifdef LOG_DEBUG
		_logit(LOG_INFO, "%s unloaded for %s", LIB, pname);
#endif

	}
}



