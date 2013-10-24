#include <stdlib.h>
#include <stdio.h>

#include "melf.h"

int main(int argc, char **argv)
{
	MELF *melf = melf_open(argv[0]);

	if (!melf)
	{
		fprintf(stdout, "couldn't open '%s'\n", argv[0]);
		return 0;
	}

	melf_save(melf, "example/testnew");

	melf_destroy(melf);

	return 1;
}
