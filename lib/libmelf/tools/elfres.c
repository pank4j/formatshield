#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <ctype.h>

#include "melf.h"

#define OPERATION_LIST   0x0001
#define OPERATION_ADD    0x0002
#define OPERATION_REM    0x0003
#define OPERATION_PRINT  0x0004
#define OPERATION_UPDATE 0x0005

unsigned long listResources(const char *image);
unsigned long printResource(const char *image, unsigned long id);
unsigned long addResource(unsigned long mode, const char *input, const char *output, Elf32_ResType type, unsigned long id, const char *string, const char *file);
unsigned long removeResource(const char *input, const char *output, unsigned long id);

int main(int argc, char **argv)
{
	const char *inputImage = NULL, *outputImage = NULL, *string = NULL, *file = NULL;
	unsigned long mode = 0, result = 0, id = 0;
	Elf32_ResType type = ELF_RES_TYPE_UNKNOWN;
	extern char *optarg;
	int c;

	while ((c = getopt(argc, argv, "lhupart:n:s:f:i:o:I:")) != EOF)
	{
		switch (c) 
		{
			case 'h':
				fprintf(stderr, "Usage: elfres [-u/-p/-l/-a/-r] [-t type] [-s string] [-f file]\n"
									 "              [-I id] [-i input img] [-o output img]\n\n"
									 "       -p --> print a resource specified by an id.\n"
									 "       -u --> update a resource.\n"
									 "       -l --> list resources in the specified input file.\n"
									 "       -a --> add a resource to the specified input file\n"
									 "              and store it in the output file, if specified.\n"
									 "       -r --> remove a resource to the specified input file\n"
									 "              and store it in the output file, if specified.\n"
									 "              the resource is identified by an index (-n).\n");
				return 0;
			case 'l':
				mode = OPERATION_LIST;
				break;
			case 'p':
				mode = OPERATION_PRINT;
				break;
			case 'a':
				mode = OPERATION_ADD;
				break;
			case 'r':
				mode = OPERATION_REM;
				break;
			case 'u':
				mode = OPERATION_UPDATE;
				break;
			case 't':
				if (!strcasecmp(optarg, "binary")) 
					type = ELF_RES_TYPE_BINARY;
				else if (!strcasecmp(optarg, "string")) 
					type = ELF_RES_TYPE_STRING;
				else
					type = ELF_RES_TYPE_UNKNOWN;
				break;
			case 's':
				string = optarg;
				break;
			case 'f':
				file = optarg;
				break;
			case 'I':
				id = strtoul(optarg, NULL, 10);
				break;
			case 'i':
				inputImage = optarg;
				break;
			case 'o':
				outputImage = optarg;
				break;
			default:
				break;
		}
	}

	if (!inputImage)
	{
		fprintf(stderr, "elfres: No input file was specified.\n");
		return 0;
	}

	if (!outputImage)
		outputImage = inputImage;

	switch (mode)
	{
		case OPERATION_LIST:
			result = listResources(inputImage);
			break;
		case OPERATION_PRINT:
			if (!id)
				fprintf(stderr, "elfres: no identifier was specified (-I).\n");
			else
				result = printResource(inputImage, id);
			break;
		case OPERATION_ADD:
		case OPERATION_UPDATE:
			if (!id)
				fprintf(stderr, "elfres: no identifier was specified (-I).\n");
			else if (!string && !file)
				fprintf(stderr, "elfres: no data source was specified (-s/-f).\n");
			else
				result = addResource(mode, inputImage, outputImage, type, id, string, file);
			break;
		case OPERATION_REM:
			if (!id)
				fprintf(stderr, "elfres: no identifier was specified (-I).\n");
			else
				result = removeResource(inputImage, outputImage, id);
			break;
		default:
			fprintf(stderr, "elfres: unknown mode of operation.\n");
			break;
	}

	if (!result)
		fprintf(stderr, "elfres: the operation did not complete successfully.\n");

	return result;
}

unsigned long listResources(const char *image)
{
	unsigned long result = 0, index = 0;
	ELF_SPEC_HEADER *res = NULL;
	MELF *melf           = melf_open(image);
	Elf32_Res current;

	do
	{
		if (!melf)
		{
			fprintf(stderr, "elfres: could not open elf image. (%s)\n", image);
			break;
		}

		if (!(res = melf_resOpen(melf)))
		{
			fprintf(stderr, "elfres: could not find resources in image.\n");
			break;
		}

		fprintf(stdout, "Listing resource from '%s'...\n\n", image);

		while (melf_resEnum(melf, res, index++, &current))
		{
			const char *type = NULL;

			switch (current.header.type)
			{
				case ELF_RES_TYPE_STRING:
					type = "string";
					break;
				case ELF_RES_TYPE_BINARY:
					type = "binary";
					break;
				default:
					type = "unknown";
					break;
			}

			fprintf(stdout, "Resource  #%.4lu:\n"
								 "  Type  : %s\n"
								 "  Length: %lu\n"
								 "  Id    : %lu\n", index, type, current.header.length, current.header.identifier);
		}

		result = 1;

	} while (0);

	if (res)
		melf_resClose(melf, res);
	if (melf)
		melf_destroy(melf);

	return result;
}

unsigned long printResource(const char *image, unsigned long id)
{
	unsigned long result = 0;
	ELF_SPEC_HEADER *res = NULL;
	MELF *melf           = melf_open(image);
	Elf32_Res current;
	char *type = NULL;

	do
	{
		if (!melf)
		{
			fprintf(stderr, "elfres: could not open elf image. (%s)\n", image);
			break;
		}

		if (!(res = melf_resOpen(melf)))
		{
			fprintf(stderr, "elfres: could not find resources in image.\n");
			break;
		}

		if (!melf_resGetId(melf, res, id, &current))
		{
			fprintf(stderr, "elfres: could not find resource %lu in image.\n", id);
			break;
		}

		switch (current.header.type)
		{
			case ELF_RES_TYPE_STRING:
				type = "string";
				break;
			case ELF_RES_TYPE_BINARY:
				type = "binary";
				break;
			default:
				type = "unknown";
				break;
		}

		fprintf(stdout, "Resource  #%.4lu:\n"
							 "  Type  : %s\n"
							 "  Length: %lu\n"
							 "  Id    : %lu\n"
							 "-- Start data --\n", current.index, type, current.header.length, current.header.identifier);

		switch (current.header.type)
		{
			case ELF_RES_TYPE_STRING:
				fprintf(stdout, "%s", (char *)current.data);
				break;
			case ELF_RES_TYPE_BINARY:
			default:
				{
					unsigned char *data = (unsigned char *)current.data;
					unsigned long x = 0, y = 0;

					for (x = 0; 
							x < current.header.length;
							x++)
					{
						fprintf(stdout, "%.2x ", data[x]);

						if ((x+1) % 10 == 0 || x+1 == current.header.length)
						{
							fprintf(stdout, "\t");

							for (; y <= x; y++)
							{
								if (isascii(data[y]))
									fprintf(stdout, "%c", data[y]);
								else
									fprintf(stdout, ".");
							}

							fprintf(stdout, "\n");

							y = x + 1;
						}
					}
				}
				break;
		}

		fprintf(stdout, "\n-- End data --\n");

		result = 1;

	} while (0);

	if (res)
		melf_resClose(melf, res);
	if (melf)
		melf_destroy(melf);

	return result;

}

unsigned long addResource(unsigned long mode, const char *input, const char *output, Elf32_ResType type, unsigned long id, const char *string, const char *file)
{
	unsigned long result = 0;
	ELF_SPEC_HEADER *res = NULL;
	MELF *melf           = melf_open(input);
	void *data           = NULL;
	unsigned long length = 0;

	do
	{
		if (!melf)
		{
			fprintf(stderr, "elfres: could not open elf image. (%s)\n", input);
			break;
		}

		if (!(res = melf_resCreate(melf)))
		{
			fprintf(stderr, "elfres: could not create resource section in image.\n");
			break;
		}

		if (string)
		{
			data   = (void *)string;
			length = strlen(string) + 1;
		}
		else if (file)
		{
			struct stat statbuf;
			FILE *fd = NULL;

			do
			{
				if (stat(file, &statbuf) != 0)
					break;

				if (!(fd = fopen(file, "r")))
					break;

				if (!(data = malloc((length = statbuf.st_size))))
					break;

				fread(data, 1, length, fd);

			} while (0);

			if (fd)
				fclose(fd);
		}

		if (!data || !length)
		{
			fprintf(stderr, "elfres: the data you provided was invalid.\n");
			break;
		}

		if (mode == OPERATION_UPDATE)
		{
			if (!melf_resUpdate(melf, res, type, length, id, data))
			{
				fprintf(stderr, "elfres: the resource could not be updated.\n");
				break;
			}
		}
		else if (!melf_resAdd(melf, res, type, length, id, data))
		{
			fprintf(stderr, "elfres: the resource could not be added.  perhaps the id is in use.\n");
			break;
		}

		result = 1;

	} while (0);

	if (result)
		melf_save(melf, output);

	if (res)
		melf_resClose(melf, res);
	if (melf)
		melf_destroy(melf);

	return result;
}

unsigned long removeResource(const char *input, const char *output, unsigned long id)
{
	unsigned long result = 0;
	ELF_SPEC_HEADER *res = NULL;
	MELF *melf           = melf_open(input);
	Elf32_Res curr;

	do
	{
		if (!melf)
		{
			fprintf(stderr, "elfres: could not open elf image. (%s)\n", input);
			break;
		}

		if (!(res = melf_resCreate(melf)))
		{
			fprintf(stderr, "elfres: could not create resource section in image.\n");
			break;
		}

		if (!melf_resGetId(melf, res, id, &curr))
		{
			fprintf(stderr, "elfres: could not find resource %lu.\n", id);
			break;
		}

		if (!melf_resRemove(melf, res, &curr))
		{
			fprintf(stderr, "elfres: could not remove resource %lu.\n", id);
			break;
		}

		result = 1;

	} while (0);

	if (result)
		melf_save(melf, output);

	if (res)
		melf_resClose(melf, res);
	if (melf)
		melf_destroy(melf);

	return result;
}
