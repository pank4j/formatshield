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

ELF_SPEC_HEADER *melf_stringTableCreate(MELF *melf, const char *name)
{
	ELF_SPEC_HEADER *sect = melf_sectionAdd(melf);

	if (!sect)
		return NULL;

	if (name)
		melf_sectionSetName(melf, sect, name);

	melf_sectionSetType(melf, sect, SHT_STRTAB);
#ifdef SHF_STRINGS
	melf_sectionSetFlags(melf, sect, SHF_ALLOC | SHF_STRINGS);
#else
	melf_sectionSetFlags(melf, sect, SHF_ALLOC);
#endif

	// Set initial blank string.
	sect->content            = (void *)malloc(1);
	sect->contentLength      = 1;
	*((char *)sect->content) = 0;

	return sect;
}

unsigned long melf_stringTableSetString(MELF *melf, ELF_SPEC_HEADER *stringTable, const char *name)
{
	unsigned long nameLength = (name) ? strlen(name) : 0;
	unsigned long index = 0;
	char *content = NULL;

	do
	{
		if (!nameLength)
			break;

		// If the string table has no contents yet, build an empty one with the name
		if (!stringTable->content)
		{
			if (!(stringTable->content = (void *)malloc((stringTable->contentLength = nameLength + 2))))
				break;

			content = (char *)stringTable->content;

			memset(content, 0, stringTable->contentLength);

			// Copy the name
			strcpy(content + 1, name);

			// Index is one in.
			index = 1;
		}
		else
		{
			unsigned long current = 0, null = 0;

			content = (char *)stringTable->content;

			while (current < stringTable->contentLength)
			{
				for (null = current; 
						null < stringTable->contentLength && content[null] != 0;
						null++);

				// If this was simply a null byte, continue.
				if (null - current == 0)
				{
					current++;

					continue;
				}

				// If the string at the current instance matches the name for null - current bytes
				// if (!strncmp(content + current, name, null - current))
				if (!strcmp(content + current, name))
				{
					index = current;
					break;
				}

				current = null;
			}

			// If we failed to find the string, we shall add it.
			if (index == 0 && *name)
			{
				if (!(stringTable->content = (void *)realloc(stringTable->content, stringTable->contentLength + nameLength + 1)))
				{
					stringTable->content = (void *)content;

					break;
				}

				strcpy((char *)((stringTable->content)) + stringTable->contentLength, name);

				index = stringTable->contentLength;

				stringTable->contentLength += nameLength + 1;
			}
		}

	} while (0);

	return index;
}

const char *melf_stringTableGetString(MELF *melf, ELF_SPEC_HEADER *stringTable, unsigned long index)
{

	if (stringTable && stringTable->contentLength > index)
		return (char *)((stringTable->content)) + index;

	return NULL;
}
