/*
 * uninformed research
 * -------------------
 *
 * ELF manipulation library
 *
 * skape
 * mmiller@hick.org
 * 02/01/2003
 */
#ifndef _MELF_INTERNAL_H
#define _MELF_INTERNAL_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>

#include <netinet/in.h>

/* Deepak */
ELF_SPEC_HEADER *_melf_listPrepend(ELF_SPEC_HEADER_LIST *list, void *header, unsigned long headerLength, void *content, unsigned long contentLength); 
ELF_SPEC_HEADER *_melf_listAppend(ELF_SPEC_HEADER_LIST *list, void *header, unsigned long headerLength, void *content, unsigned long contentLength); 
unsigned long    _melf_listRemove(ELF_SPEC_HEADER_LIST *list, unsigned long id);
unsigned long    _melf_listFlush(ELF_SPEC_HEADER_LIST *list);

#endif
