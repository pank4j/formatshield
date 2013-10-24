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
#include "melf.h"

void _melf_loadSections(MELF *melf, unsigned long base);
void _melf_loadPrograms(MELF *melf, unsigned long base);

void _melf_updatePrograms(MELF *melf);

MELF *melf_new()
{
	MELF *melf = (MELF *)malloc(sizeof(MELF));

	if (!melf)
		return NULL;

	memset(melf, 0, sizeof(MELF));

	memcpy(melf->header.e_ident, ELFMAG, SELFMAG);

	melf->header.e_type     = ET_NONE;
	melf->header.e_machine  = EM_NONE;
	melf->header.e_ident[4] = ELFCLASS32;
#if defined(ELF_BIG_ENDIAN)
	melf->header.e_ident[5] = ELFDATA2MSB;
#else
	melf->header.e_ident[5] = ELFDATA2LSB;
#endif
	melf->header.e_ident[6] = melf->header.e_version = EV_CURRENT;

	return melf;
}

MELF *melf_open(const char *image)
{
	MELF *melf = (MELF *)malloc(sizeof(MELF));
	/* To avoid errors due to stray non zero bytes in the melf, zero out melf- Avijit Mar 28, 2004*/
	bzero(melf,sizeof(MELF));

	unsigned char success = 0;
	unsigned long base = 0;
	struct stat statbuf;
	int fd = 0;

	if (!melf)
		return NULL;

	memset(melf, 0, sizeof(melf));

	strncpy(melf->image, image, sizeof(melf->image) - 1);

	do
	{
		// Can we read it?
		if ((fd = open(melf->image, O_RDONLY)) <= 0)
			break;

		// Is the size compatible?
		if ((fstat(fd, &statbuf) != 0) || (statbuf.st_size < sizeof(Elf32_Ehdr)))
			break;

		melf->imageSize = statbuf.st_size;

		// Can we mmap it?
		if (!(base = (unsigned long)mmap(NULL, melf->imageSize, PROT_READ, MAP_PRIVATE, fd, 0))){

			break;
		}


		// Is it a potential elf image?
		if (memcmp((void *)base, ELFMAG, SELFMAG)){

			break;
		}

		memcpy(&melf->header, (void *)base, sizeof(Elf32_Ehdr));
		melf->programs.length=0;
		melf->programs.head=melf->programs.tail=NULL;


		_melf_loadPrograms(melf, base);
		/* Explicitely Set the sections.length  to 0 -- Avijit 16 Dec*/
		melf->sections.length=0;
		melf->sections.head=melf->sections.tail=NULL;
		_melf_loadSections(melf, base);

		success = 1;

	} while (0);

	if (base)
		munmap((void *)base, statbuf.st_size);
	if (fd > 0)
		close(fd);
	if (!success)
		melf_destroy(melf), melf = NULL;
#ifdef DEBUG
	printf("header->e_shstrndx= %d\n",melf->header.e_shstrndx);
	printf("Contents of shstrtab are :\n");
	ELF_SPEC_HEADER *shstrtab=melf_sectionFindIndex(melf,melf->header.e_shstrndx);
	int i;
	for(i=0;i<shstrtab->contentLength;i++)
	  printf("%c",*(char *)(shstrtab->content+i)>31?*(char *)(shstrtab->content+i):'.');
	printf("\n");
#endif

	return melf;
}

void melf_destroy(MELF *melf)
{
	_melf_listFlush(&melf->sections);
	_melf_listFlush(&melf->programs);

	free(melf);
}

// Compare two sections - which should appear first in the file
MELF *global_melf;
int _melf_compareSections(const void *p1, const void *p2) {
	ELF_SPEC_HEADER *s1 = *((ELF_SPEC_HEADER **)(p1));
	ELF_SPEC_HEADER *s2 = *((ELF_SPEC_HEADER **)(p2));
	Elf32_Word f1 = melf_sectionGetFlags(global_melf, s1);
	Elf32_Word f2 = melf_sectionGetFlags(global_melf, s2);
	unsigned long l1 = s1->contentLength;
	unsigned long l2 = s2->contentLength;
	/* NULL section is smaller than any other section -- Avijit Feb 16*/
	if(melf_sectionGetType(global_melf,s1)==SHT_NULL)
	  return -1;
	if(melf_sectionGetType(global_melf,s2)==SHT_NULL)
	  return 1;

	if ((f1 & SHF_ALLOC) && !(f2 & SHF_ALLOC))
		return -1;
	if ((f2 & SHF_ALLOC) && !(f1 & SHF_ALLOC))
		return 1;
	if (!(f2 & SHF_ALLOC) && !(f1 & SHF_ALLOC))
		return 0;
	/* both occupy space in memory */
	if (l1 == 0 && l2 > 0)
		return 1;
	if (l1 > 0 && l2 == 0)
		return -1;
	if (l1 == 0 && l2 == 0)
		return 0;
	/* content length for both is non-zero */
	/* just check whose va is lesser */
	return melf_sectionGetAddress(global_melf,s1) -
		melf_sectionGetAddress(global_melf,s2);
}



// Deepak - return a sorted array of sections
// last element in the array is null
ELF_SPEC_HEADER ** _melf_sortSections(MELF *melf) {
	ELF_SPEC_HEADER *curr;
	int n = melf->sections.length;
	ELF_SPEC_HEADER **s = calloc(sizeof(ELF_SPEC_HEADER *),n+1);
	int i;

	for (i=0,curr = melf_sectionGetEnum(melf); curr;
	     curr = melf_sectionEnumNext(melf, curr),i++)
		s[i] = curr;
	s[n] = (ELF_SPEC_HEADER *)0;
	global_melf = melf;
	qsort(s, n, sizeof(ELF_SPEC_HEADER *), _melf_compareSections);
	return s;
}

unsigned long melf_save(MELF *melf, const char *path)
{
	unsigned long currentOffset = sizeof(Elf32_Ehdr);
	unsigned long fileSize = 0;
	ELF_SPEC_HEADER *curr;
	ELF_SPEC_HEADER **sortedsections, **p;
	void *map = NULL;
	int fd = 0;
	ELF_SPEC_HEADER *cursegment = melf_programGetEnum(melf);

	// First program headers

	melf->header.e_phnum     = melf->programs.length;
	melf->header.e_phentsize = sizeof(Elf32_Phdr);
	melf->header.e_phoff     = currentOffset;

	currentOffset += sizeof(Elf32_Phdr) * melf->programs.length;

	sortedsections = _melf_sortSections(melf);

	// Now for sections
	for (p = sortedsections,curr = *p; curr; curr = *(++p))
	/*
	for (curr = melf_sectionGetEnum(melf);
			curr;
			curr = melf_sectionEnumNext(melf, curr))
	*/

	{
	  /* Exempt the first section (of type SHT_NULL) from hte following business. This section must always
	     have VA=offset=size=0  -- Avijit Feb 16*/
	  if(curr->spec.section.sh_type==SHT_NULL){
	    curr->spec.section.sh_addr=0;
	    curr->spec.section.sh_offset=0;
	    continue;
	  }

		unsigned long remainder = 0;

		if (melf_sectionGetFlags(melf, curr) & SHF_ALLOC) {
		  // a loadable section, compute the offset based on the offset of the segment
		  // that this section belongs to.
		  while (cursegment && 
			 (cursegment->spec.program.p_vaddr > curr->spec.section.sh_addr ||
			   cursegment->spec.program.p_vaddr + cursegment->spec.program.p_memsz <
			       curr->spec.section.sh_addr))
		    cursegment = melf_programEnumNext(melf, cursegment);
		  if (cursegment) /* section belongs to this segment */
		    currentOffset = cursegment->spec.program.p_offset + curr->spec.section.sh_addr -
		                      cursegment->spec.program.p_vaddr;
		}
		
		// Calculate page alignment
		if (curr->spec.section.sh_addralign > 1)
		{
			unsigned long mask = (currentOffset & (curr->spec.section.sh_addralign - 1));

			if (mask)
				remainder = curr->spec.section.sh_addralign - mask;
		}

		currentOffset += remainder;

		curr->spec.section.sh_offset = currentOffset;
		curr->spec.section.sh_size   = curr->contentLength;

		if (curr->spec.section.sh_type != SHT_NOBITS)
			currentOffset += curr->contentLength;

	}
	
	melf->header.e_shnum     = melf->sections.length;
	melf->header.e_shentsize = sizeof(Elf32_Shdr);
	melf->header.e_shoff     = currentOffset;
	
	currentOffset += sizeof(Elf32_Shdr) * melf->sections.length;

	// Update program headers to the right sizes based of section references & offsets.
	// _melf_updatePrograms(melf);      

	// Set the file size
	fileSize = currentOffset;

	if (!path)
		path = melf->image;

	do
	{
		unsigned long offset = 0, currSize = fileSize, diff = 4096;
		char null[diff];

		memset(null, 0, diff);

		if ((fd = open(path, O_RDWR | O_TRUNC | O_CREAT, 0755)) <= 0)
			break;

		while (currSize)
		{
			unsigned long amt = (currSize < diff) ? currSize : diff;

			write(fd, null, amt);

			currSize -= amt;
		}

		if ((map = mmap(NULL, fileSize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)) <= 0)
			break;

		memcpy(map, &melf->header, sizeof(Elf32_Ehdr));

		offset += sizeof(Elf32_Ehdr);

		// Write program headers
		for (curr = melf_programGetEnum(melf);
				curr;
				curr = melf_programEnumNext(melf, curr))
		{
			memcpy(map + offset, &curr->spec.program, sizeof(Elf32_Phdr));

			offset += sizeof(Elf32_Phdr);
		}

		// Write sections
		for (p = sortedsections,curr = *p; curr; curr = *(++p))
		/*
		for (curr = melf_sectionGetEnum(melf);
				curr;
				curr = melf_sectionEnumNext(melf, curr))
		*/
		{
			if (curr->content)
			{
				memcpy(map + curr->spec.section.sh_offset, curr->content, curr->contentLength);

				offset = curr->spec.section.sh_offset + curr->spec.section.sh_size;
			}
		}
		// deepak
		free(sortedsections);

		// Write section headers
		for (curr = melf_sectionGetEnum(melf);
				curr;
				curr = melf_sectionEnumNext(melf, curr))
		{
			memcpy(map + offset, &curr->spec.section, sizeof(Elf32_Shdr));

			offset += sizeof(Elf32_Shdr);
		}

		msync(map, fileSize, MS_SYNC);

	} while (0);

	if (map)
		munmap(map, fileSize);
	if (fd > 0)
		close(fd);

	return 1;
}

void _melf_loadSections(MELF *melf, unsigned long base)
{
	Elf32_Shdr *fSections = (Elf32_Shdr *)((base + melf->header.e_shoff));
	unsigned long x = 0;

	do
	{
		// Make sure someone isn't being evil.
		if (IS_OVERFLOW(melf, base, fSections) || IS_OVERFLOW(melf, base, fSections + melf->header.e_shnum))
			break;

		for (; x < melf->header.e_shnum; x++)
		{
			// Make sure the content size is alright.
			if (fSections[x].sh_type != SHT_NOBITS && ((IS_OVERFLOW(melf, base, base + fSections[x].sh_offset)) ||
				 (IS_OVERFLOW(melf, base, base + fSections[x].sh_offset + fSections[x].sh_size))))
				continue;

			_melf_listAppend(&melf->sections, 
								 		(void *)((fSections + x)),
										sizeof(Elf32_Shdr),
										(void *)((base + fSections[x].sh_offset)),
										fSections[x].sh_size);
		}

	} while (0);
}

void _melf_loadPrograms(MELF *melf, unsigned long base)
{
	Elf32_Phdr *fPrograms = (Elf32_Phdr *)((base + melf->header.e_phoff));
	unsigned long x = 0;

	do
	{
		if (IS_OVERFLOW(melf, base, fPrograms) || IS_OVERFLOW(melf, base, fPrograms + melf->header.e_phnum))
			break;


		for (; x < melf->header.e_phnum; x++)
		{
			_melf_listAppend(&melf->programs, 
								 		(void *)((fPrograms + x)),
										sizeof(Elf32_Shdr),
										NULL,
										0);
		}



	} while (0);
}

void _melf_updatePrograms(MELF *melf)
{
	ELF_SPEC_HEADER *section = NULL, *prog = NULL;
	unsigned long diff;

	for (prog = melf_programGetEnum(melf);
			prog;
			prog = melf_programEnumNext(melf, prog))
	{
		diff = 0;

		// Deepak
		
		if (melf_programGetType(melf,prog) == PT_PHDR)
		  continue;
		
		/*
		if (prog->spec.program.p_memsz > prog->spec.program.p_filesz)
			diff = prog->spec.program.p_memsz - prog->spec.program.p_filesz;

		prog->spec.program.p_filesz = 0;
		*/

		for (section = melf_sectionGetEnum(melf);
				section;
				section = melf_sectionEnumNext(melf, section)) {
			if (section->spec.section.sh_addr >= prog->spec.program.p_vaddr &&
			    (/*!prog->spec.program.p_memsz || */
						section->spec.section.sh_addr < prog->spec.program.p_vaddr + prog->spec.program.p_memsz))
			{
				
			        /*
			        prog->spec.program.p_filesz += section->spec.section.sh_size;

				if (section->spec.section.sh_addr == prog->spec.program.p_vaddr)
					prog->spec.program.p_offset = section->spec.section.sh_offset;
				*/
			        prog->spec.program.p_offset = section->spec.section.sh_offset - 
				  (section->spec.section.sh_addr - prog->spec.program.p_vaddr);
				break;
			}
		}

		/*
		prog->spec.program.p_memsz = prog->spec.program.p_filesz;

		if (diff)
			prog->spec.program.p_memsz += diff;
		*/
	}
}
