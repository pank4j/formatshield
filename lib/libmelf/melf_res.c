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

ELF_SPEC_HEADER *melf_resOpen(MELF *melf)
{
	return melf_sectionFindType(melf, SHT_RES);
}

ELF_SPEC_HEADER *melf_resCreate(MELF *melf)
{
	ELF_SPEC_HEADER *res = melf_sectionFindType(melf, SHT_RES);

	if (res)
		return res;

	if (!(res = melf_sectionAdd(melf)))
		return NULL;

	melf_sectionSetName(melf, res, ".res");
	melf_sectionSetType(melf, res, SHT_RES);

	return res;
}

unsigned char melf_resEnum(MELF *melf, ELF_SPEC_HEADER *resTable, unsigned long index, Elf32_Res *res)
{
	unsigned char *current = (unsigned char *)resTable->content;
	unsigned long offset = 0, c = 0, length = 0;

	if (!current)
		return 0;

	// While we're not going past our buffer and we haven't reached our index, enumerate
	while (((offset + (sizeof(struct _Elf32_Res_Header))) < resTable->contentLength) && 
				(c < index))
	{
		length  = ntohl(*(unsigned long *)(current+offset));
		offset += length; // Increment offset by the current pointer;
		c++;
	}

	if (((offset + sizeof(struct _Elf32_Res_Header)) >= resTable->contentLength) ||
			(c != index))
		return 0;

	res->index             = index;
	res->offset            = offset;
	res->header.length     = ntohl(*(unsigned long *)(current+offset)) - sizeof(struct _Elf32_Res_Header);
	res->header.type       = ntohl(*(unsigned long *)(current+offset+sizeof(unsigned long)));
	res->header.identifier = ntohl(*(unsigned long *)(current+offset+sizeof(unsigned long)+sizeof(unsigned long)));

	if (res->header.length)
		res->data = (void *)(current+offset+sizeof(struct _Elf32_Res_Header));
	else
		res->data = NULL;

	return 1;
}

unsigned char melf_resGetType(MELF *melf, ELF_SPEC_HEADER *resTable, Elf32_ResType type, Elf32_Res *res)
{
	unsigned long index = 0;
	unsigned char found = 0;

	while (melf_resEnum(melf, resTable, index++, res))
	{
		if (res->header.type == type)
		{
			found = 1;
			break;
		}
	}

	return found;
}

unsigned char melf_resGetId(MELF *melf, ELF_SPEC_HEADER *resTable, unsigned long id, Elf32_Res *res)
{
	unsigned long index = 0;
	unsigned char found = 0;

	while (melf_resEnum(melf, resTable, index++, res))
	{
		if (res->header.identifier == id)
		{
			found = 1;
			break;
		}
	}

	return found;
}

unsigned char melf_resAdd(MELF *melf, ELF_SPEC_HEADER *resTable, Elf32_ResType type, unsigned long length, unsigned long id, void *data)
{
	struct _Elf32_Res_Header *header = NULL;
	unsigned long originalLength = resTable->contentLength;
	unsigned long newLength      = originalLength + sizeof(struct _Elf32_Res_Header) + length;
	unsigned char *newBuffer     = NULL;
	unsigned char *payload       = NULL;
	unsigned char result         = 0;
	Elf32_Res verify;

	// Make sure something with this identifier does not exist.
	if (melf_resGetId(melf, resTable, id, &verify))
		return 0;

	do
	{
		if (!(newBuffer = (unsigned char *)realloc(resTable->content, newLength)))
			break;

		header  = (struct _Elf32_Res_Header *)(newBuffer + originalLength);
		payload = newBuffer + originalLength + sizeof(struct _Elf32_Res_Header);

		// Initialize the header
		header->length     = htonl(length + sizeof(struct _Elf32_Res_Header)); // Length includes both header and payload
		header->identifier = htonl(id);
		header->type       = htonl(type);

		// Initialize the payload
		memcpy(payload, data, length);

		// And we're done.
		resTable->content       = newBuffer;
		resTable->contentLength = newLength;

		result = 1;

	} while (0);

	return result;
}

unsigned char melf_resUpdate(MELF *melf, ELF_SPEC_HEADER *resTable, Elf32_ResType type, unsigned long length, unsigned long id, void *data)
{
	Elf32_Res current;

	if (melf_resGetId(melf, resTable, id, &current))
		melf_resRemove(melf, resTable, &current);

	return melf_resAdd(melf, resTable, type, length, id, data);
}

unsigned char melf_resRemove(MELF *melf, ELF_SPEC_HEADER *resTable, Elf32_Res *res)
{
	unsigned char *base        = (unsigned char *)resTable->content;
	unsigned long shrinkLength = res->header.length + sizeof(struct _Elf32_Res_Header);
	unsigned long newLength    = resTable->contentLength - (shrinkLength);
	unsigned long baseOffset   = 0;
	unsigned char *shrink      = base + res->offset;

	if (newLength)
		resTable->content = malloc(newLength);
	else
	{
		free(base);

		resTable->content       = NULL;
		resTable->contentLength = 0;

		return 1;
	}

	memset(resTable->content, 0, newLength);

	// Copy front
	if (shrink - base)
		memcpy(resTable->content, 
							 base, 
							 (baseOffset = shrink - base));
	// Copy back
	if ((shrink + shrinkLength) - base != resTable->contentLength)
		memcpy(resTable->content + baseOffset,
							 shrink + shrinkLength,
							 (base + resTable->contentLength) - (shrink + shrinkLength));

	free(base);

	resTable->contentLength = newLength;

	return 1;
}

void melf_resClose(MELF *melf, ELF_SPEC_HEADER *resTable)
{
}
