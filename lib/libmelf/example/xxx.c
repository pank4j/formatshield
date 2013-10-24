#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "melf.h"
#define PAGE_SIZE 0x1000

#ifndef ELF32_ST_OTHER
#define ELF32_ST_OTHER(v) ((v)&0x3)
#endif

int nbuckets=0;
ELF_SPEC_HEADER *old_dynsym=NULL,*old_dynstr=NULL,*old_hash=NULL,*old_dynamic=NULL;
int old_dynsym_size=0,old_dynstr_size=0,old_hash_size=0,old_dynamic_size=0;
int new_symbol_size=0;
char *new_symbol_name;

/* Addresses and sizes of new sections */
int dynsym_addr,dynsym_size,dynstr_addr,dynstr_size,hash_addr,hash_size,newdata_addr,newdata_size,newsymbol_size; 
int extra_pages=1;/* Fix it for now */
MELF *melf;
unsigned long elf_hash(const unsigned char *name){
  unsigned long   h = 0, g;
  while (*name){
    h = (h << 4) + *name++;
    if ((g = h & 0xf0000000))
      h ^= g >> 24;
    h &= ~g;
  }
  return h;
}

int calculate_extra_pages(int size_of_data){
  /* Returns the total number of pages needed to hold various sections and the data of size  size_of_data 
     Add the number of bytes needed and round-off to the nearest page-size
     Assumes that sizes of various sections have been calculated a priori 
  */
  int pages= (int)(size_of_data+dynsym_size+dynstr_size+hash_size/PAGE_SIZE)+
    (size_of_data+dynsym_size+dynstr_size+hash_size)%PAGE_SIZE?1:0;
  assert(pages>0);
  return pages;

}

void add_new_chain(unsigned long bucket, int hash_data[],int last_entry){
  /* Adds a new chain in the hash_data. The last 4 bytes are assumed to be free in hash_data for this appending
     Other chains are adjusted as follows:
     
     The first chain corresponding to bucket is found out. Suppose this entry turns out to be index.
     The following changes are made:
     The entry in bucket[bucke]t is changed to point to the last index i.e. our symbol 
     The chain[last index] is made equal to the index the entry was earlier pointing to 
     If this was STN_UNDEF, the chain[last index] is made STN_UNDEF
  */
  nbuckets=(int)*hash_data;
  printf("Total Buckets: %d\n",nbuckets);
  int prev_chain_leader=hash_data[2+bucket%nbuckets];
  hash_data[2+last_entry+nbuckets]=prev_chain_leader;
  hash_data[1]=hash_data[1]+1;
  hash_data[2+bucket%nbuckets]=last_entry;
  return;
}

int init(char *file){
  /* Initialize the melf data structure */
  melf = melf_open(file);
  if (!melf){
    fprintf(stderr, "melf_open failed\n");
    return 1;
  }
  return 0;
}

void find_sections(void){
  /* Locate dynsym dynstr and hash sections and set the appropriate variables */
  /* Also Calculates the sizes of the new sections that will be created */
  ELF_SPEC_HEADER *sections=melf_sectionGetEnum(melf);
  while(sections){
    /* Iterate over the sectiobs fixing the variables */
    if(!strcmp(melf_sectionGetName(melf,sections),".dynsym")){
      old_dynsym=sections;
      old_dynsym_size=sections->spec.section.sh_size;
      dynsym_size=old_dynsym_size+melf_sectionGetEntrySize(melf,sections);
    }
    if(!strcmp(melf_sectionGetName(melf,sections),".dynstr")){
      old_dynstr=sections;
      old_dynstr_size=sections->spec.section.sh_size;
      dynstr_size=old_dynstr_size+new_symbol_size;
    }
    if(!strcmp(melf_sectionGetName(melf,sections),".hash")){
      old_hash=sections;
      old_hash_size=sections->spec.section.sh_size;
      hash_size=old_hash_size+sizeof(void *);
    }
    if(!strcmp(melf_sectionGetName(melf,sections),".dynamic")){
      old_dynamic=sections;
      old_dynamic_size=sections->spec.section.sh_size;
    }
    sections=melf_sectionEnumNext(melf,sections);
  }
}

void calculate_new_addresses(int new_symbol_size){
  /* Calculates the addresses of the 4 new sections to be formed */

  int start=0xfffff000&melf_elfGetEntry(melf);
  int elf_header_size=sizeof(Elf32_Ehdr);
  int prog_header_size=sizeof(Elf32_Phdr)*melf_elfGetProgramHeaderCount(melf);
  dynsym_addr=start-extra_pages*PAGE_SIZE+elf_header_size+prog_header_size;
  dynstr_addr=dynsym_addr+old_dynsym_size+melf_sectionGetEntrySize(melf,old_dynsym);
  assert(dynsym_size==dynstr_addr-dynsym_addr);
  hash_addr=dynstr_addr+old_dynstr_size+new_symbol_size;
  assert(dynstr_size==hash_addr-dynstr_addr);
  newdata_addr=hash_addr+old_hash_size+melf_sectionGetEntrySize(melf,old_hash);
  assert(hash_size==newdata_addr-hash_addr);
  printf("Calculated the new addresses as : dynsym: 0x%x, dynstr: 0x%x, hash: 0x%x, data: 0x%x\n",
	  dynsym_addr,dynstr_addr,hash_addr,newdata_addr);
  printf("New Sizes: dynsym: 0x%x, dynstr 0x%x, hash: 0x%x, data: 0x%x\n",
	 dynsym_size,dynstr_size,hash_size,newdata_size);
  return;
}


int main(int argc, char **argv)
{
  ELF_SPEC_HEADER *curr = NULL, *progh = NULL , *new_dynsym = NULL, *new_dynstr = NULL,*newhash=NULL;
 



  int new_symbol_index=-1;
  int i=0;/* A Counter */
 
  char *contents;
  new_symbol_name=(char *)malloc(sizeof("new_symbol_avijit"));
  char *tmp="new_symbol_avijit";
  for(i=0;i<sizeof("new_symbol_avijit");i++)
    new_symbol_name[i]=*(tmp+i);
  new_symbol_name[sizeof("new_symbol_avijit")-1]='\0';
  new_symbol_size=sizeof("new_symbol_avijit");
  char *dynsym_data,*dynstr_data;
  int *hash_data;
  int first_load_segment = 1;
  unsigned long hash_bucket=elf_hash(new_symbol_name);
  Elf32_Addr dynamic_section_addr=0;
  ELF_SPEC_HEADER *dynamic_segment = NULL;

 

  if (argc != 4){
    fprintf(stderr, "Usage: %s <input-file> <output-file> <new data>\n",argv[0]);
    return 0;
  }
  printf("Displaying the data to be inserted: %s\n",argv[3]);
  if(init(argv[1])){
    exit(1);
  }
  find_sections();
  extra_pages=calculate_extra_pages(sizeof(*argv[3]));
  calculate_new_addresses(new_symbol_size);
  printf("Extra Pages required: %d\n",extra_pages);

  curr=melf_sectionAdd(melf);
  new_dynsym = melf_sectionAdd(melf);
  new_dynstr = melf_sectionAdd(melf);
  newhash=melf_sectionAdd(melf);


  newdata_size=PAGE_SIZE*extra_pages-dynsym_size-dynstr_size-hash_size;
  printf("new data size recalculated: 0x%x\n",newdata_size);
  contents=(char *)malloc(newdata_size);
  dynsym_data=(char *)malloc(old_dynsym_size+melf_sectionGetEntrySize(melf,old_dynsym));
  dynstr_data=(char *)malloc(old_dynstr_size+new_symbol_size);
  hash_data=(int*)malloc(old_hash_size+4);
  strcpy(contents, argv[3]);   
    
  /* Fixing dynsym section */
  void *prev_dynsym_contents=melf_sectionGetContent(melf,old_dynsym);
  bcopy(prev_dynsym_contents,dynsym_data,old_dynsym_size);
  /* Calculating the index of the symbol to be added */
  new_symbol_index=old_dynsym_size/melf_sectionGetEntrySize(melf,old_dynsym);

  printf(".dynsym contents:\n");
  for(i=0;i<old_dynsym_size;i++)
    printf("%c ",dynsym_data[i]>31?dynsym_data[i]:'.');
  printf("\n");
  /* Add the entry for pointing to corresponding entry in the .dynstr */
  char new_entry[16];
  for(i=0;i<16;i++)
    new_entry[i]=(char)0x0;
 
 /* Calculating the index of new symbol in the dynstr */
  int new_index=old_dynstr_size;   /* Remember that index in dynstr is really the offset from start of section */
  Elf32_Sym *elf_sym=(Elf32_Sym *)malloc(sizeof(Elf32_Sym));
  elf_sym->st_name=new_index;
  elf_sym->st_value=newdata_addr;
  elf_sym->st_size=new_symbol_size;
  elf_sym->st_info=ELF32_ST_INFO(STB_GLOBAL,STT_OBJECT);
  elf_sym->st_other=ELF32_ST_OTHER(STV_DEFAULT);
  elf_sym->st_shndx=(Elf32_Half)melf_sectionGetIndex(melf,curr);

  for(i=0;i<16;i++){
    dynsym_data[i+old_dynsym_size]=*(char *)((void*)elf_sym+i)/*new_entry[i]*/;
    printf("Emitting : 0x%d\n",new_entry[i]);
  }

      
  /* Change the pointer of new_dynsym to that of the old dynsym */

      
  melf_sectionSetContent(melf,new_dynsym,prev_dynsym_contents,old_dynsym_size);
  melf_sectionSetType(melf,new_dynsym,SHT_PROGBITS);
  melf_sectionSetAddress(melf,new_dynsym,old_dynsym->spec.section.sh_addr);
  melf_sectionSetFlags(melf, new_dynsym, SHF_ALLOC);
     
  /* Set the dynsym section properly */
  melf_sectionSetAddress(melf,old_dynsym,dynsym_addr);
  melf_sectionSetContent(melf,old_dynsym,dynsym_data,old_dynsym_size+melf_sectionGetEntrySize(melf,old_dynsym));


  /* Fixing dynstr */
  void *prev_dynstr_contents=melf_sectionGetContent(melf,old_dynstr);
  bcopy(prev_dynstr_contents,dynstr_data,old_dynstr_size);
  for(i=0;i<new_symbol_size;i++)
    dynstr_data[old_dynstr_size+i]=new_symbol_name[i];
    
  printf(".dynstr contents:\n");
  printf("New symbol size= %d\n",new_symbol_size);
  for(i=0;i<old_dynstr_size+new_symbol_size;i++)
    printf("%c ",dynstr_data[i]>31?dynstr_data[i]:'.');
  printf("\n");
  printf("Contents copied dynstr: %s\n",dynstr_data);

  melf_sectionSetContent(melf,new_dynstr,prev_dynstr_contents,old_dynstr_size);
  melf_sectionSetType(melf,new_dynstr,SHT_PROGBITS);
  melf_sectionSetAddress(melf,new_dynstr,old_dynstr->spec.section.sh_addr);
  melf_sectionSetFlags(melf, new_dynstr, SHF_ALLOC);

  melf_sectionSetAddress(melf,old_dynstr,dynstr_addr);
  melf_sectionSetContent(melf,old_dynstr,dynstr_data,old_dynstr_size+new_symbol_size);
      
  /* Done Fixing dynsym and dynstr */

   
 

   
  /* Fix hash section */


  void *prev_hash_contents=melf_sectionGetContent(melf,old_hash);
  hash_data=malloc(old_hash_size+4);
  bcopy(prev_hash_contents,hash_data,old_hash_size);
  melf_sectionSetContent(melf,newhash,prev_hash_contents,old_hash_size);
  melf_sectionSetType(melf,newhash,SHT_PROGBITS/*melf_sectionGetType(melf,old_hash)*/);
  melf_sectionSetAddress(melf,newhash,old_hash->spec.section.sh_addr);
  melf_sectionSetFlags(melf, newhash,SHF_ALLOC/*melf_sectionGetFlags(melf,old_hash)*/);

  /* Calculate hash value of new symbol and insert it in the chain properly */
  printf("Printing out the original contents of .hash\n");
  for(i=0;i<old_hash->spec.section.sh_size/4;i++)
    printf("%d\n",(int)*(hash_data+i));
  add_new_chain(hash_bucket,hash_data,new_symbol_index);
  printf("Hash bucket is: %ld\n",hash_bucket%nbuckets);
  printf("Printing out the new hash table\n");
  for(i=0;i<sizeof(hash_data);i++)
    printf("0x%x\n",hash_data[i]&0xff);
  /* Set the hash table properly */
  melf_sectionSetAddress(melf,old_hash,hash_addr);
  melf_sectionSetContent(melf,old_hash,hash_data,old_hash_size+4);     
  /* Done Fixing hash section */

   


  if (!curr) {
    fprintf(stderr, "Cannot create new section\n");
    return 1;
  }

  melf_sectionSetType(melf, curr, SHT_PROGBITS);
  melf_sectionSetFlags(melf, curr, SHF_ALLOC);
  melf_sectionSetAddress(melf, curr, newdata_addr);
 
  melf_sectionSetContent(melf, curr, contents,newdata_size);	
  
  // change the segment map
	
  progh = melf_programGetEnum(melf);
  while (progh) {
    switch (melf_programGetType(melf, progh)) {
    case PT_PHDR:
      melf_programSetVirtualAddress(melf, progh,
				    melf_programGetVirtualAddress(melf, progh) -
				    PAGE_SIZE*extra_pages);
      melf_programSetPhysicalAddress(melf, progh,
				     melf_programGetPhysicalAddress(melf, progh) -
				     PAGE_SIZE*extra_pages);
      break;
    case PT_LOAD:
      if (first_load_segment) {
	melf_programSetVirtualAddress(melf, progh,
				      melf_programGetVirtualAddress(melf, progh) -
				      PAGE_SIZE*extra_pages);
	melf_programSetPhysicalAddress(melf, progh,
				       melf_programGetPhysicalAddress(melf, progh) -
				       PAGE_SIZE*extra_pages);
	melf_programSetPhysicalSize(melf, progh,
				    melf_programGetPhysicalSize(melf, progh) +
				    PAGE_SIZE*extra_pages);
	melf_programSetVirtualSize(melf, progh,
				   melf_programGetVirtualSize(melf, progh) +
				   PAGE_SIZE*extra_pages);
	first_load_segment = 0;
      } else
	progh->spec.program.p_offset += PAGE_SIZE*extra_pages;
      break;
    case PT_DYNAMIC:
      dynamic_section_addr=progh->spec.section.sh_addr;
      dynamic_segment=progh;

    case PT_INTERP:
    default:
      progh->spec.program.p_offset += PAGE_SIZE*extra_pages;
      break;
    }
    progh = melf_programEnumNext(melf, progh);
  }
 

  if(!melf_dynamicSetTag(melf,old_dynamic,DT_SYMTAB,dynsym_addr)||
     !melf_dynamicSetTag(melf,old_dynamic,DT_STRTAB,dynstr_addr)||
     !melf_dynamicSetTag(melf,old_dynamic,DT_HASH,hash_addr)){
    fprintf(stderr,"Error in reassigning pointers iin .dynamic\n");
    return 1;
  }
  melf_save(melf, argv[2]);
  melf_destroy(melf);
  return 0;
}
