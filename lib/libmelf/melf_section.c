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

/* Deepak - insert a new section in the beginning */
ELF_SPEC_HEADER *melf_sectionInsert(MELF *melf)
{
	ELF_SPEC_HEADER *n =
	       	_melf_listPrepend(&melf->sections, NULL, 0, NULL, 0);
	melf_elfSetStringTableIndex(melf,
			melf_elfGetStringTableIndex(melf)+1);
	return n;
}


ELF_SPEC_HEADER *melf_sectionAdd(MELF *melf)
{
	return _melf_listAppend(&melf->sections, NULL, 0, NULL, 0);
}

ELF_SPEC_HEADER *melf_sectionGetEnum(MELF *melf)
{
	return melf->sections.head;
}

ELF_SPEC_HEADER *melf_sectionEnumNext(MELF *melf, ELF_SPEC_HEADER *en)
{
	return (en) ? en->next : NULL;
}

ELF_SPEC_HEADER *melf_sectionEnumPrev(MELF *melf, ELF_SPEC_HEADER *en)
{
	return (en) ? en->prev : NULL;
}

ELF_SPEC_HEADER *melf_sectionFindType(MELF *melf, unsigned long type)
{
	ELF_SPEC_HEADER *curr = NULL;

	for (curr = melf_sectionGetEnum(melf);
			curr;
			curr = melf_sectionEnumNext(melf, curr))
	{
		if (curr->spec.section.sh_type == type)
			break;
	}

	return curr;
}

ELF_SPEC_HEADER *melf_sectionFindIndex(MELF *melf, unsigned long index)
{
	ELF_SPEC_HEADER *curr = NULL;

	for (curr = melf_sectionGetEnum(melf);
			curr;
			curr = melf_sectionEnumNext(melf, curr))
	{
		if (curr->index == index)
			break;
	}

	return curr;
}

ELF_SPEC_HEADER *melf_sectionFindName(MELF *melf, const char *name)
{
	ELF_SPEC_HEADER *curr = NULL;

	for (curr = melf_sectionGetEnum(melf);
			curr;
			curr = melf_sectionEnumNext(melf, curr))
	{
		const char *sec = melf_sectionGetName(melf, curr);		

		if ((sec) && (!strcmp(name, sec)))
			break;
	}

	return curr;
}

void melf_sectionSetStringTableHeader(MELF *melf, ELF_SPEC_HEADER *section, ELF_SPEC_HEADER *stringTable)
{
	section->spec.section.sh_link = melf_sectionGetIndex(melf, stringTable);
}

ELF_SPEC_HEADER *melf_sectionGetStringTableHeader(MELF *melf, ELF_SPEC_HEADER *section)
{
	ELF_SPEC_HEADER *ret = NULL;

	if (section->spec.section.sh_link > melf->sections.length)
		return NULL;

	ret = melf_sectionFindIndex(melf, section->spec.section.sh_link);

	if (ret->spec.section.sh_type != SHT_STRTAB)
		return NULL;

	return ret;
}

void melf_sectionSetContent(MELF *melf, ELF_SPEC_HEADER *section, void *content, unsigned long contentLength)
{
	if (section->content)
		free(section->content);

	section->contentLength = 0;

	if (contentLength)
	{
		if ((section->content = (void *)malloc(contentLength)))
			memcpy(section->content, content, (section->contentLength = contentLength));
	}
	else
		section->content = NULL;

	section->spec.section.sh_size = section->contentLength;
}

void *melf_sectionGetContent(MELF *melf, ELF_SPEC_HEADER *section)
{
	return (section) ? section->content : NULL;
}

void melf_sectionSetName(MELF *melf, ELF_SPEC_HEADER *section, const char *name)
{
	ELF_SPEC_HEADER *stringSection = melf_sectionFindIndex(melf, melf->header.e_shstrndx);
	unsigned long index = 0;

	// If no string table exists or one cannot be found...
	if (!stringSection || melf_sectionGetType(melf, stringSection) != SHT_STRTAB)
	{
		stringSection = melf_stringTableCreate(melf, NULL);

		if (stringSection)
		{
			melf_elfSetStringTableIndex(melf, melf_sectionGetIndex(melf, stringSection));

			melf_sectionSetName(melf, stringSection, ".shstrtab");
		}
	}

	// Now add the string to the string table.
	if ((index = melf_stringTableSetString(melf, stringSection, name)) != -1)
		section->spec.section.sh_name = index;
}

const char *melf_sectionGetName(MELF *melf, ELF_SPEC_HEADER *section)
{
	ELF_SPEC_HEADER *stringSection = melf_sectionFindIndex(melf, melf->header.e_shstrndx);


	return (stringSection) ? melf_stringTableGetString(melf, stringSection, section->spec.section.sh_name) : "";
}

void melf_sectionSetType(MELF *melf, ELF_SPEC_HEADER *section, unsigned long type)
{
	if (section)
		section->spec.section.sh_type = type;
}

unsigned long melf_sectionGetType(MELF *melf, ELF_SPEC_HEADER *section)
{
	return (section) ? section->spec.section.sh_type : SHT_NULL;
}

void melf_sectionSetAddress(MELF *melf, ELF_SPEC_HEADER *section, Elf32_Addr addr)
{
	if (section)
		section->spec.section.sh_addr = addr;
}

Elf32_Addr melf_sectionGetAddress(MELF *melf, ELF_SPEC_HEADER *section)
{
	return (section) ? section->spec.section.sh_addr : 0;
}

void melf_sectionSetFlags(MELF *melf, ELF_SPEC_HEADER *section, Elf32_Word flags)
{
	if (section)
		section->spec.section.sh_flags = flags;
}

Elf32_Word melf_sectionGetFlags(MELF *melf, ELF_SPEC_HEADER *section)
{
	return (section) ? section->spec.section.sh_flags : 0;
}

void melf_sectionSetEntrySize(MELF *melf, ELF_SPEC_HEADER *section, Elf32_Word entsize)
{
	if (section)
		section->spec.section.sh_entsize = entsize;
}

Elf32_Word melf_sectionGetEntrySize(MELF *melf, ELF_SPEC_HEADER *section)
{
	return (section) ? section->spec.section.sh_entsize : 0;
}

unsigned long melf_sectionGetIndex(MELF *melf, ELF_SPEC_HEADER *section)
{
	return (section) ? section->index : -1;	
}

unsigned long melf_sectionRemove(MELF *melf, unsigned long id)
{
	return _melf_listRemove(&melf->sections, id);
}
