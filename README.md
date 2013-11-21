# [Formatshield](http://www.codepwn.com/2009/06/formatshield.html) release 1.0
 

FormatShield is a library that intercepts call to vulnerable functions and uses binary rewriting to defend against format string attacks. It identifies the vulnerable call sites in a running process and dumps the corresponding context information in the ELF binary of the process. Attacks are detected when format specifiers are found at these contexts of the vulnerable call sites.

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

For more info, visit [http://www.codepwn.com/2009/06/formatshield.html](http://www.codepwn.com/2009/06/formatshield.html).


## Usage

The library can be preloaded into a process using LD_PRELOAD environment variable.
```
export LD_PRELOAD=/path/to/libfshield.so
/path/program_to_protect
```


## Copyright and License

Formatshield is released under [GNU GPL v3](COPYING).

Copyright (C) 2007 Centre for Security, Theory and Algorithmic Research (CSTAR), IIIT, Hyderabad, India.
Copyright (C) Pankaj Kohli

