/* $Name: release1.0 $
 * $Id: binwrite.c,v 1.0 Jan 2, 2008 Pankaj Kohli $
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


#include "binwrite.h"


MELF *melf;
ELF_SPEC_HEADER *old_dynsym=NULL, *old_dynstr=NULL, *old_hash=NULL, *old_dynamic=NULL; 		/* Old Sections */
ELF_SPEC_HEADER *dynsym=NULL, *dynstr=NULL, *hash=NULL, *curr=NULL; 						/* New sections */
unsigned long pagesize;
unsigned long old_dynsym_size, old_dynstr_size, old_hash_size, old_dynamic_size;					/* Old section sizes */
unsigned long dynsym_size, dynstr_size, hash_size, dynamic_size, new_symbol_size;					/* New section sizes */
unsigned long new_dynsym_addr, new_dynstr_addr, new_hash_addr;								/* New VMAs */



/*
	Finds a new virtual address where the new sections can be loaded.
	Also calculates the new virtual address if the section already exists (oldsize != 0)
*/
unsigned long getnewvma(unsigned long newsize, unsigned long oldsize) {
	ELF_SPEC_HEADER *en;
	unsigned long top=0xffffffff, pg1, pg2;

	/* Locate the lowest virtual address of any loadable section */
	for ( en=melf_sectionGetEnum(melf); en != NULL; en=melf_sectionEnumNext(melf, en) ) {
		if ( (en->spec.section.sh_flags & SHF_ALLOC) && (en->spec.section.sh_addr < top) ) {
			top = en->spec.section.sh_addr;
		}
	}
	
	pg1 = numpagesrqd(newsize, pagesize);
	pg2 = numpagesrqd(oldsize, pagesize);
	return (top - ((pg1-pg2)*pagesize));
}


/*
	Updates the PHDR to accomodate the new section
*/
void update_phdr(unsigned long newsize, unsigned long oldsize) {
	ELF_SPEC_HEADER *en;

	for ( en=melf_programGetEnum(melf); en != NULL; en=melf_programEnumNext(melf, en) ) {
		if ( (melf_programGetType(melf, en)==PT_LOAD) && (melf_programGetFlags(melf, en) & PF_X) ) {		/* Segment is loadable & executable (segment containing the new section) */
			
			/* Increase the physical & virtual size */
			en->spec.program.p_filesz += (newsize - oldsize);
			en->spec.program.p_memsz += (newsize - oldsize);
			
			/* Extend the physical & virtual address towards lower addresses */
			en->spec.program.p_vaddr -= (newsize - oldsize);
			en->spec.program.p_paddr -= (newsize - oldsize);
			
		} else if ( melf_programGetType(melf, en) == PT_PHDR ) {
			
			/* Load PHDR at lower address */
			en->spec.program.p_vaddr -= (newsize - oldsize);
			en->spec.program.p_paddr -= (newsize - oldsize);
			
		} else {
		
			/* For all other segments, increase the file offset */
			en->spec.program.p_offset += (newsize - oldsize);
			
		}
	}
}



/*
	Finds .dynsym, .dynstr, .hash & .dynamic sections
*/
void find_sections(void){
	ELF_SPEC_HEADER *en;
 
	for ( en=melf_sectionGetEnum(melf); en != NULL; en=melf_sectionEnumNext(melf, en) ) {
		if (old_dynamic && old_hash && old_dynstr && old_dynsym)
			break;																	/* All found */
		
		if ( (melf_sectionGetType(melf, en) == SHT_DYNSYM) ) {
			
			/* .dynsym found */
			old_dynsym = en;
			old_dynsym_size = en->spec.section.sh_size;
			dynsym_size = old_dynsym_size + melf_sectionGetEntrySize(melf, en);
			
		}
		
		if ( (melf_sectionGetType(melf, en) == SHT_STRTAB) && (!strcmp(melf_sectionGetName(melf, en), ".dynstr")) ) {
			
			/* .dynstr found */
			old_dynstr = en;
			old_dynstr_size = en->spec.section.sh_size;
			dynstr_size = old_dynstr_size + new_symbol_size;

			/* Align to 4-bytes */
			if ( dynstr_size%4 != 0 ) {
				dynstr_size += (4 - (dynstr_size%4));
			}
			
		}
		
		if ( melf_sectionGetType(melf, en) == SHT_HASH ) {
			
			/* .hash found */
			old_hash = en;
			old_hash_size = en->spec.section.sh_size;
			hash_size = old_hash_size + sizeof(void *);
			
		}
	
		if ( (melf_sectionGetType(melf, en) == SHT_DYNAMIC) ) {
			
			/* .dynamic found */
			old_dynamic = en;
			old_dynamic_size = en->spec.section.sh_size;
			
		}
	}
}


/*
	Computes hash of name
*/
unsigned long elf_hash(const unsigned char *name) {
	unsigned long   h = 0, g;

	while ( *name ) {
    		h = (h << 4) + *name++;
    		if ( (g = h & 0xf0000000) )
      			h ^= g >> 24;
    		h &= ~g;
  	}
  	
  	return h;
}


/*
	Adds a new chain to the hash data
*/
void add_new_chain(unsigned long bucket, int hash_data[],int last_entry) {
	int nbuckets = hash_data[0];
	int prev_chain_leader = hash_data[2+(bucket%nbuckets)];

	hash_data[2+(last_entry+nbuckets)] = prev_chain_leader;
	hash_data[1] = hash_data[1]+1;
	hash_data[2+(bucket%nbuckets)] = last_entry;
}



/*
	Adds a new section of given size that replaces the given section sec.
	The VMA for the new section is set to that of the section sec. VMA for the section sec
	must be changed when the function returns.
	Returns pointer to the new section (containing data of old section sec)
*/
ELF_SPEC_HEADER *add_section(ELF_SPEC_HEADER *sec, void *content, unsigned long size) {
	ELF_SPEC_HEADER *en = melf_sectionAdd(melf);
	void *data = malloc(sec->spec.section.sh_size);
	unsigned long addr = sec->spec.section.sh_addr;

	melf_sectionSetName(melf, en, "");
	en->spec.section.sh_type = SHT_PROGBITS;
	en->spec.section.sh_flags = sec->spec.section.sh_flags;
	memcpy(data, melf_sectionGetContent(melf, sec), sec->spec.section.sh_size);
	melf_sectionSetContent(melf, en, data, sec->spec.section.sh_size);
	melf_sectionSetContent(melf, sec, content, size);
	sec->spec.section.sh_addr = 0;
	melf_sectionSetAddress(melf, en, addr);
	en->spec.section.sh_addralign = sec->spec.section.sh_addralign;
	free(data);

	return en;
}



/*
	Dumps data of length datasize into the new section of the binary in the new elf binary out.
	New section is created if it does not exists or extended towards
	lower addresses if it cannot hold data of length datasize.
	Returns 0 on success, 1 on error.
	New section is structured as 
	________________________________________________________
	|MAGIC	|PAGES		|BASE	|DATA	|		DATA		|
	|NUMBER	|EXTENDED	|		|LENGTH	|					|
	-------------------------------------------------------------------------------------
*/
int dump(char *binary, char *out, void *data, int datasize) {
	ELF_SPEC_HEADER *en;
	unsigned long vma, size, ind, oldsize, bucket;
	char *ptr, *dynsym_data, *dynstr_data, *new_symbol;
	Elf32_Sym *sym;
	int i, *hash_data;
	Dl_info info;

	if( !(melf = melf_open(binary)) ) return 1;
	
	new_symbol_size = sizeof(SECTION_NAME);
	new_symbol = (char *) malloc(sizeof(SECTION_NAME));
	for ( i=0, ptr=SECTION_NAME; *ptr; ptr++ ) {
		new_symbol[i++] = *ptr;
	}
	new_symbol[i] = 0;
	find_sections();
	
	if ( (curr = melf_sectionFindName(melf, SECTION_NAME)) ) {
		/* Section already present */
		
		/* Calculate oldsize and newsize */
		oldsize = numpagesrqd(curr->spec.section.sh_size+old_dynsym_size+old_dynstr_size+old_hash_size, pagesize) * pagesize;
		size = numpagesrqd(datasize+16+old_dynsym_size+old_dynstr_size+old_hash_size, pagesize) * pagesize;		/* sizeof(MAGIC_NUMBER) +sizeof(extend) + sizeof(datasize) = 12 */
		
		ptr = malloc(size);
		if(! ptr) return 1;
		dladdr((void *) curr->spec.section.sh_addr, &info);
		*((int *) ptr) = MAGIC_NUMBER;											/* Magic number */
		*((int *) (ptr+4)) = size/pagesize;										/* Number of pages by which binary is extended */
		*((int *) (ptr+8)) = (uint32_t) info.dli_fbase;								/* Base address */
		*((int *) (ptr+12)) = datasize;											/* Size of the context hash list */
		memcpy(ptr+16, data, datasize);
	
		if ( size > oldsize ) {					/* Updating the binary is only required if the context list size has increased */
			vma = getnewvma(datasize+16+old_dynstr_size+old_dynsym_size+old_hash_size, curr->spec.section.sh_size+old_dynstr_size+old_dynsym_size+old_hash_size);
			melf_sectionSetAddress(melf, curr, vma);

			/* Fix .dynsym */
			for ( i=0; (sym=melf_symbolTableEnum(melf, old_dynsym, i)); i++ ) {
				if ( strcmp(melf_symbolGetName(melf, old_dynsym, sym), new_symbol) == 0 ) {
					melf_symbolSetValue(melf, old_dynsym, sym, vma);
			  		break;
				}
			}
			
			/* Fix SHDR */
			curr->spec.section.sh_size += (size - oldsize);
			ind = melf_sectionGetIndex(melf, curr);
			for ( i=0; (en=melf_sectionFindIndex(melf, i)); i++ ) {
				if ( melf_sectionGetIndex(melf, en) > ind ) {
					en->spec.section.sh_offset += (size - oldsize);
				}
			}
			melf_sectionSetContent(melf, curr, ptr, size-old_dynsym_size-old_dynstr_size-old_hash_size);
			update_phdr(size, oldsize);
			if ( melf_save(melf, out) ) i = 0; else i = 1;
		} else i = 1;						/* No rewriting required if size of context hash list not changed */
	} else {
		/* Section not already present */
		
		/* Calculate New VMAs */
		size = numpagesrqd(datasize+16+dynsym_size+dynstr_size+hash_size, pagesize) * pagesize;
		vma = getnewvma(datasize+16+dynstr_size+dynsym_size+hash_size, 0);
		new_dynsym_addr = vma + size - dynsym_size - dynstr_size - hash_size;
		new_dynstr_addr = vma + size - dynstr_size - hash_size;
		new_hash_addr = vma + size - hash_size;

		/* Add a new section */
		ptr = malloc(size);
		if(! ptr) return 1;
		*((int *) ptr) = MAGIC_NUMBER;
		*((int *) (ptr+4)) = size/pagesize;
		*((int *) (ptr+8)) = vma - (vma % pagesize);
		*((int *) (ptr+12)) = datasize;
		memcpy(ptr+16, data, datasize);
		curr = melf_sectionAdd(melf);
		melf_sectionSetContent(melf, curr, ptr, size-dynsym_size-dynstr_size-hash_size);
		melf_sectionSetName(melf, curr, SECTION_NAME);
		melf_sectionSetType(melf, curr, SHT_PROGBITS);
		melf_sectionSetFlags(melf, curr, SHF_ALLOC);
		melf_sectionSetAddress(melf, curr, vma);


		/* Replace existing .dynsym section */
		dynsym_data = malloc(dynsym_size);
		memcpy(dynsym_data, melf_sectionGetContent(melf, old_dynsym), old_dynsym_size);
		sym = (Elf32_Sym *) malloc(sizeof(Elf32_Sym));
		sym->st_name = old_dynstr_size;
  		sym->st_value = curr->spec.section.sh_addr;
  		sym->st_size = sizeof(SECTION_NAME);
  		sym->st_info = ELF32_ST_INFO(STB_GLOBAL, STT_OBJECT);
		sym->st_other = ELF32_ST_OTHER(STV_DEFAULT);
		sym->st_shndx = melf_sectionGetIndex(melf, curr);
  		for ( i=0; i < 16; i++ ) {
    			dynsym_data[i+old_dynsym_size] = *((char *) ((void*)sym+i));
  		}
		dynsym = add_section(old_dynsym, dynsym_data, dynsym_size);
		melf_sectionSetAddress(melf, old_dynsym, new_dynsym_addr);


		/* Replace exisiting .dynstr section */
		dynstr_data = malloc(dynstr_size);
		memcpy(dynstr_data, melf_sectionGetContent(melf, old_dynstr), old_dynstr_size);
		for ( i=0; i < new_symbol_size; i++ ) {
			*(dynstr_data + old_dynstr_size + i) = *(new_symbol + i);
		}
		dynstr = add_section(old_dynstr, dynstr_data, dynstr_size);
		melf_sectionSetAddress(melf, old_dynstr, new_dynstr_addr);


		/* Replace existing .hash section */
		hash_data = malloc(hash_size);
		memcpy(hash_data, melf_sectionGetContent(melf, old_hash), old_hash_size);
		bucket = elf_hash((const unsigned char *) SECTION_NAME);
		add_new_chain(bucket, hash_data, old_dynsym_size/melf_sectionGetEntrySize(melf, old_dynsym));
		hash = add_section(old_hash, hash_data, hash_size);
		melf_sectionSetAddress(melf, old_hash, new_hash_addr);


		/* Fix .dynamic section */
		melf_dynamicSetTag(melf, old_dynamic, DT_SYMTAB, vma+size-dynsym_size-dynstr_size-hash_size);
		melf_dynamicSetTag(melf, old_dynamic, DT_STRTAB, vma+size-dynstr_size-hash_size);
		melf_dynamicSetTag(melf, old_dynamic, DT_HASH, vma+size-hash_size);
		melf_dynamicSetTag(melf, old_dynamic, DT_STRSZ, dynstr_size);

		update_phdr(size, 0);		
		if ( melf_save(melf, out) ) i = 0; else i = 1;
		free(sym);
		free(dynsym_data);
		free(dynstr_data);
		free(hash_data);
	}

	free(ptr);
	melf_destroy(melf);
	return i;
}



/*
	Loads the contents of the new section of the binary
	Returns number of bytes loaded from the section
	(NOT USED)
*/
int load(char *binary, void **ptr) {
	int *content;
	int datasize;
	ELF_SPEC_HEADER *en;
	
	if( !(melf = melf_open(binary)) ) return 0;
	
	if ( (en = melf_sectionFindName(melf, SECTION_NAME)) ) {
		content = melf_sectionGetContent(melf, en);
		if ( (*content == MAGIC_NUMBER) && (*(content+1) > 0) && ((datasize = *(content+3)) > 0) ) {
			if( (*ptr = malloc(datasize)) ) {
				memcpy(*ptr, content+16, datasize);
				melf_destroy(melf);
				return datasize;
			}
		}
	}
	
	melf_destroy(melf);
	return 0;
}



