#include <stdlib.h>
#include <stdio.h>

#include "melf.h"

int main(int argc, char **argv)
{
	ELF_SPEC_HEADER *curr = NULL;
	MELF *melf = melf_open(argv[0]);

	if (!melf)
	{
		fprintf(stdout, "failed\n");
		return 0;
	}

	if ((curr = melf_sectionAdd(melf)))
	{
		melf_sectionSetName(melf, curr, ".sig");

		melf_sectionSetType(melf, curr, SHT_NOBITS);
	}

	melf_save(melf, "out");

	melf_destroy(melf);

	return 1;
}
