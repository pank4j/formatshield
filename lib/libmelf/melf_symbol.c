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

void melf_symbolSetName(MELF *melf, ELF_SPEC_HEADER *symTable, Elf32_Sym *sym, const char *name)
{
	ELF_SPEC_HEADER *stringTable = melf_sectionGetStringTableHeader(melf, symTable);

	if (stringTable)
		sym->st_name = melf_stringTableSetString(melf, stringTable, name);
	else
		sym->st_name = 0;
}

const char *melf_symbolGetName(MELF *melf, ELF_SPEC_HEADER *symTable, Elf32_Sym *sym)
{
	ELF_SPEC_HEADER *stringTable = melf_sectionGetStringTableHeader(melf, symTable);

	if (stringTable)
		return melf_stringTableGetString(melf, stringTable, sym->st_name);

	return NULL;
}

void melf_symbolSetValue(MELF *melf, ELF_SPEC_HEADER *symTable, Elf32_Sym *sym, Elf32_Addr value)
{
	if (sym)
		sym->st_value = value;
}

Elf32_Addr melf_symbolGetValue(MELF *melf, ELF_SPEC_HEADER *symTable, Elf32_Sym *sym)
{
	return (sym) ? sym->st_value : 0;
}

void melf_symbolSetSize(MELF *melf, ELF_SPEC_HEADER *symTable, Elf32_Sym *sym, Elf32_Word size)
{
	if (sym)
		sym->st_size = size;
}

Elf32_Word melf_symbolGetSize(MELF *melf, ELF_SPEC_HEADER *symTable, Elf32_Sym *sym)
{
	return (sym) ? sym->st_size : 0;
}

void melf_symbolSetBinding(MELF *melf, ELF_SPEC_HEADER *symTable, Elf32_Sym *sym, unsigned char binding)
{
	if (sym)
		sym->st_info |= binding << 4;
}

unsigned char melf_symbolGetBinding(MELF *melf, ELF_SPEC_HEADER *symTable, Elf32_Sym *sym)
{
	return (sym) ? sym->st_info >> 4 : 0;
}

void melf_symbolSetType(MELF *melf, ELF_SPEC_HEADER *symTable, Elf32_Sym *sym, unsigned char type)
{
	if (sym)
		sym->st_info = (sym->st_info & 0xf0) + (type & 0xf);
}

unsigned char melf_symbolGetType(MELF *melf, ELF_SPEC_HEADER *symTable, Elf32_Sym *sym)
{
	return (sym) ? sym->st_info & 0xf : 0;
}

void melf_symbolSetSectionIndex(MELF *melf, ELF_SPEC_HEADER *symTable, Elf32_Sym *sym, Elf32_Half shndx)
{
	if (sym)
		sym->st_shndx = shndx;
}

Elf32_Half melf_symbolGetSectionIndex(MELF *melf, ELF_SPEC_HEADER *symTable, Elf32_Sym *sym)
{
	return (sym) ? sym->st_shndx : 0;
}
