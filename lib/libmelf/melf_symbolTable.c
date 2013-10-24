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

Elf32_Sym *_melf_symbolTableAllocateSym(ELF_SPEC_HEADER *symbolTable);
void _melf_symbolTableShrink(ELF_SPEC_HEADER *symbolTable, Elf32_Sym *shrinkAt);

ELF_SPEC_HEADER *melf_symbolTableCreate(MELF *melf, const char *name)
{
	ELF_SPEC_HEADER *sect = melf_sectionAdd(melf);
	ELF_SPEC_HEADER *str;
	Elf32_Sym *first = NULL;

	if (!sect)
		return NULL;

	melf_sectionSetType(melf, sect, SHT_SYMTAB);
	melf_sectionSetFlags(melf, sect, SHF_ALLOC);
	melf_sectionSetEntrySize(melf, sect, sizeof(Elf32_Sym));

	if (name)
		melf_sectionSetName(melf, sect, name);

	if ((str = melf_stringTableCreate(melf, ".strtab")))
		melf_sectionSetStringTableHeader(melf, sect, str);

	// Create the first index of the symbol table.
	// name  => 0
	// value => 0
	// size  => 0
	// info  => 0
	// other => 0
	// shndx => 0
	first = melf_symbolTableAddSymbol(melf, sect, NULL);

	return sect;
}

Elf32_Sym *melf_symbolTableAddSymbol(MELF *melf, ELF_SPEC_HEADER *symTable, const char *name)
{
	Elf32_Sym *ret = NULL;

	if (!(ret = _melf_symbolTableAllocateSym(symTable)))
		return NULL;

	melf_symbolSetName(melf, symTable, ret, name);

	return ret;
}

Elf32_Sym *melf_symbolTableEnum(MELF *melf, ELF_SPEC_HEADER *symTable, unsigned long index)
{
	Elf32_Sym *table = (Elf32_Sym *)symTable->content;
	unsigned long elements = symTable->contentLength / sizeof(Elf32_Sym);

	if (index >= elements)
		return NULL;

	return table + index;
}

unsigned long melf_symbolTableRemoveSymbol(MELF *melf, ELF_SPEC_HEADER *symTable, Elf32_Sym *symbol)
{
	if (symbol)
		_melf_symbolTableShrink(symTable, symbol);

	return 1;
}

Elf32_Sym *_melf_symbolTableAllocateSym(ELF_SPEC_HEADER *symbolTable)
{
	unsigned long newLength = symbolTable->contentLength + sizeof(Elf32_Sym);
	Elf32_Sym     *base     = NULL;

	if (!symbolTable->content)
		base = (Elf32_Sym *)malloc(newLength);
	else
		base = (Elf32_Sym *)realloc(symbolTable->content, newLength);

	if (!base)
		return NULL;

	symbolTable->content        = (void *)base;
 	//(unsigned char *)base      += symbolTable->contentLength;
	base = (Elf32_Sym *) (((unsigned char *) base) + symbolTable->contentLength);
	symbolTable->contentLength  = newLength;

	memset(base, 0, sizeof(Elf32_Sym));

	return base;
}

void _melf_symbolTableShrink(ELF_SPEC_HEADER *symbolTable, Elf32_Sym *shrinkAt)
{
	Elf32_Sym *base = (Elf32_Sym *)symbolTable->content;
	unsigned long newLength = symbolTable->contentLength - sizeof(Elf32_Sym), elements = 0;
	unsigned long preElements  = 0;
	unsigned long postElements = 0;

	if (!base || !symbolTable->contentLength)
		return;

	elements = symbolTable->contentLength / sizeof(Elf32_Sym);

	if (newLength)
		symbolTable->content = (void *)malloc(newLength);
	else // Else we got rid of all the symbols
	{
		free(base);

		symbolTable->content       = NULL;
		symbolTable->contentLength = 0;

		return;
	}
	
	// From here on out the number of elements will always be greater than one.

	preElements  = shrinkAt - base;
	postElements = elements - preElements - 1;

	if (preElements)
		memcpy(symbolTable->content, base, preElements * sizeof(Elf32_Sym));
	if (postElements)
		memcpy(symbolTable->content + (preElements * sizeof(Elf32_Sym)), shrinkAt + 1, postElements * sizeof(Elf32_Sym));

	free(base);

	symbolTable->contentLength = newLength;
}
