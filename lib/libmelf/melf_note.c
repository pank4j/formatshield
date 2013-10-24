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

Elf32_Nhdr *_melf_noteAllocate(ELF_SPEC_HEADER *note, const char *name, const char *desc, unsigned long descLength);
void _melf_noteShrink(ELF_SPEC_HEADER *note, Elf32_Nhdr *shrinkAt);

ELF_SPEC_HEADER *melf_noteCreate(MELF *melf, const char *name, unsigned long createProgramHeader)
{
	ELF_SPEC_HEADER *note =	melf_sectionAdd(melf);

	if (note)
	{
		melf_sectionSetType(melf, note, SHT_NOTE);
		melf_sectionSetName(melf, note, (name) ? name : ".note");
		melf_sectionSetFlags(melf, note, SHF_ALLOC);
		melf_sectionSetAddress(melf, note, 0x20000000);
	}

	if (createProgramHeader)
	{
		ELF_SPEC_HEADER *prog = melf_programAdd(melf);

		if (prog)
		{
			melf_programSetType(melf, prog, PT_NOTE);
			melf_programSetFlags(melf, prog, PF_R);
			melf_programSetVirtualAddress(melf, prog, melf_sectionGetAddress(melf, note));
			melf_programSetPhysicalAddress(melf, prog, melf_sectionGetAddress(melf, note));
		}
	}

	return note;
}

Elf32_Nhdr *melf_noteAdd(MELF *melf, ELF_SPEC_HEADER *note, Elf32_Word type, const char *name, unsigned char *desc, unsigned long descLength)
{
	Elf32_Nhdr *item = _melf_noteAllocate(note, name, (const char *) desc, descLength);	

	if (item)
		item->n_type = type;

	return item;
}

Elf32_Nhdr *melf_noteEnum(MELF *melf, ELF_SPEC_HEADER *note, unsigned long index)
{
	Elf32_Nhdr *base = (Elf32_Nhdr *)note->content;
	unsigned char *curr = NULL;
	unsigned long cindex = 0;

	for (curr = (unsigned char *)base, cindex = 0;
			curr != (unsigned char *)(base) + note->contentLength;
			curr += sizeof(Elf32_Nhdr) + ((Elf32_Nhdr *)curr)->n_namesz + ((Elf32_Nhdr *)curr)->n_descsz, cindex++)
	{
		if (cindex == index)
			break;
	}

	return (cindex == index) ? (Elf32_Nhdr *)curr : NULL;
}

unsigned long melf_noteRemove(MELF *melf, ELF_SPEC_HEADER *note, Elf32_Nhdr *item)
{
	if (!item)
		return 0;

	_melf_noteShrink(note, item);

	return 1;
}

unsigned long melf_noteGetType(MELF *melf, ELF_SPEC_HEADER *note, Elf32_Nhdr *item)
{
	return (item) ? item->n_type : 0;
}

const char *melf_noteGetName(MELF *melf, ELF_SPEC_HEADER *note, Elf32_Nhdr *item)
{
	return (const char *) ((item && item->n_namesz) ? (unsigned char *)item + sizeof(Elf32_Nhdr) : NULL);
}

unsigned char *melf_noteGetDesc(MELF *melf, ELF_SPEC_HEADER *note, Elf32_Nhdr *item)
{
	return (item && item->n_descsz) ? (unsigned char *)item + sizeof(Elf32_Nhdr) + item->n_namesz : NULL;
}

Elf32_Nhdr *_melf_noteAllocate(ELF_SPEC_HEADER *note, const char *name, const char *desc, unsigned long descLength)
{
	unsigned long nameLength = strlen(name ? name : "");
	unsigned long newLength = note->contentLength + sizeof(Elf32_Nhdr);
	Elf32_Nhdr *base        = (Elf32_Nhdr *)note->content;

	if (nameLength % 4 != 0)
		nameLength += 4 - (nameLength %4);
	if (descLength % 4 != 0)
		descLength += 4 - (descLength %4);

	// Add padded sizes
	newLength += nameLength + descLength;

	if (!note->content)
		base = (Elf32_Nhdr *)malloc(newLength);
	else
		base = (Elf32_Nhdr *)realloc(note->content, newLength);

	if (!base)
		return NULL;

	note->content          = (void *)base;
 	//(unsigned char *)base += note->contentLength;
	base = (Elf32_Nhdr *) (((unsigned char *) base) + note->contentLength);
	
	memset(base, 0, newLength - note->contentLength);

	note->contentLength    = newLength;

	base->n_namesz = nameLength;
	base->n_descsz = descLength;

	if (name)
		strncpy((unsigned char *)base + sizeof(Elf32_Nhdr), name, nameLength);
	if (desc)
		memcpy((unsigned char *)base + sizeof(Elf32_Nhdr) + nameLength, desc, descLength);

	return base;
}

void _melf_noteShrink(ELF_SPEC_HEADER *note, Elf32_Nhdr *shrinkAt)
{
	Elf32_Nhdr *base = (Elf32_Nhdr *)note->content;
	unsigned long newLength = note->contentLength - (sizeof(Elf32_Nhdr) + shrinkAt->n_namesz + shrinkAt->n_descsz);
	unsigned long shrinkLength = sizeof(Elf32_Nhdr) + shrinkAt->n_namesz + shrinkAt->n_descsz;
	unsigned long baseOffset   = 0;

	if (!base || !note->contentLength)
		return;

	if (newLength)
		note->content = (void *)malloc(newLength);
	else // Else we got rid of all the note's
	{
		free(base);

		note->content       = NULL;
		note->contentLength = 0;

		return;
	}

	memset(note->content, 0, newLength);

	if (shrinkAt - base)
		memcpy(note->content, base, (baseOffset = (unsigned char *)(shrinkAt) - (unsigned char *)(base)));
	if ((unsigned char *)(shrinkAt) + shrinkLength - (unsigned char *)(base) != note->contentLength)
		memcpy(note->content + baseOffset, 
					(unsigned char *)(shrinkAt) + shrinkLength, 
					(unsigned char *)(base) + note->contentLength - ((unsigned char *)(shrinkAt) + shrinkLength));

	free(base);

	note->contentLength = newLength;
}
