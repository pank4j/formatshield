#include <stdlib.h>
#include <stdio.h>

#include "melf.h"

int main(int argc, char **argv)
{
	ELF_SPEC_HEADER *curr;
	MELF *melf = melf_new();

	if (!melf)
		return 0;

	fprintf(stdout, "creating new elf img called 'blank'...\n");

	melf_elfSetType(melf, ET_EXEC);
	melf_elfSetMachine(melf, EM_386);

	if ((curr = melf_sectionAdd(melf)))
	{
		melf_sectionSetName(melf, curr, "test-section");
		melf_sectionSetType(melf, curr, SHT_NOBITS);
	}
	
	if ((curr = melf_sectionAdd(melf)))
	{
		melf_sectionSetName(melf, curr, "bobby");
		melf_sectionSetType(melf, curr, SHT_NOBITS);
	}

	// Add a dynamic section
	
	if ((curr = melf_dynamicCreate(melf)))
	{
		ELF_SPEC_HEADER *dynstr = melf_sectionGetStringTableHeader(melf, curr);
		unsigned long index = 0;

		// Add DT_NEEDED for libc.
		if (dynstr)
			index = melf_stringTableSetString(melf, dynstr, "/lib/libc.so.6");

		melf_dynamicAddTag(melf, curr, DT_NEEDED, index);
	}

	// Add a note section

	if ((curr = melf_noteCreate(melf, ".note", 1)))
	{
		melf_noteAdd(melf, curr, 1, "NAZI", "JONES", 6);
		melf_noteAdd(melf, curr, 0, "NAME", "DESC", 5);
		melf_noteAdd(melf, curr, 1, "JANE", "DESCZ", 5);
	}

	// Add a symbol table
	
	if ((curr = melf_symbolTableCreate(melf, ".symtab")))
	{
		Elf32_Sym *sym = melf_symbolTableAddSymbol(melf, curr, "tester");
		sym = melf_symbolTableAddSymbol(melf, curr, "shutup");

		melf_symbolSetType(melf, curr, sym, STT_OBJECT);
		melf_symbolSetBinding(melf, curr, sym, STB_GLOBAL);
	}

	melf_save(melf, "blank");

	melf_destroy(melf);

	return 1;
}
