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
/**
 * @defgroup melf The Manipulate ELF library.
 *
 * The manipulate ELF library.
 */
/**
 * @addtogroup melf
 *
 * @{
 */
/**
 * @example new.c
 * Generates a new ELF binary with a few different types of sections.
 */
#ifndef _MELF_H
#define _MELF_H

#ifdef MELF_COMP
	#include "stdelf.h"
#else
	#include <stdelf.h>
#endif

#define IS_OVERFLOW(melf, base, addr) ((melf)->imageSize < ((unsigned long)(addr) - (unsigned long)(base)))

/**
 * Wrappers both section and program headers.
 *
 * @short ELF Specific header.
 */
typedef struct _elf_spec_header {

	/**
	 * The index associated with the given header
	 */
	unsigned long           index;
	/**
	 * The unique identifier for the section
	 */
	unsigned long           identifier;

	/**
	 * The union for either section or program header.
	 */
	union
	{

		/**
		 * The section header data.
		 */
		Elf32_Shdr section;
		/**
		 * The program header data.
		 */
		Elf32_Phdr program;

	} spec;

	/**
	 * The content held in the section, if any.
	 */
	void                    *content;
	/**
	 * The number of bytes of content.
	 */
	unsigned long           contentLength;

	/**
	 * The previous specific header in the list.
	 */
	struct _elf_spec_header *prev;
	/**
	 * The next specific header in the list.
	 */
	struct _elf_spec_header *next;

} ELF_SPEC_HEADER;

/**
 * A list that contains one or more specific headers.
 *
 * @short Specific header list.
 */
typedef struct _elf_spec_header_list {

	/**
	 * The first header in the list.
	 */
	ELF_SPEC_HEADER *head;
	/**
	 * The last header in the list.
	 */
	ELF_SPEC_HEADER *tail;

	/**
	 * The current unique identifier sequence pool.
	 */
	unsigned long   seq;
	/**
	 * The number of items in the list.
	 */
	unsigned long   length;

} ELF_SPEC_HEADER_LIST;

/**
 * The melf context used to hold the path to an image as well as the elf, program and section headers.
 *
 * @short MELF context.
 */
typedef struct _melf {

	/**
	 * The path to the ELF image being operated on.
	 */
	char                 image[1024];
	/**
	 * The size, in bytes, of the image.
	 */
	unsigned long        imageSize;

	/**
	 * The ELF header for the current ELF image.
	 */
	Elf32_Ehdr           header;

	/**
	 * The list of sections
	 */
	ELF_SPEC_HEADER_LIST sections;

	/**
	 * The list of program sections.
	 */
	ELF_SPEC_HEADER_LIST programs;

} MELF;

/**
 * Creates a blank MELF context.
 *
 * @return On success, a newly allocated MELF context is returned, otherwise NULL is returned.
 */
MELF *melf_new();
/**
 * Translates an ELF image into a MELF context which can then be editted.
 *
 * @param  image [in] The path to the image to edit.
 * @return On success, a newly allocated MELF context is returned, otherwise NULL is returned.
 */
MELF *melf_open(const char *image);
/**
 * Destroys a MELF context, deallocating all memory associated with it.
 *
 * @param  melf [in] The context to destroy.
 */
void melf_destroy(MELF *melf);

/**
 * Saves a MELF context in ELF format to the specified path.
 *
 * @param  melf [in] The context to translate from.
 * @param  path [in] The path to the image to write to.
 * @return On success, 1 is returned.
 */
unsigned long melf_save(MELF *melf, const char *path);

/**
 * @}
 */

// Elf header functions

/**
 * @defgroup elfheader ELF Header
 * @ingroup  melf
 *
 * @{
 */

/**
 * Sets the type of the binary
 *
 * The type can be one of the following:
 *
 * @li ET_NONE 
 * 		No type.
 * @li ET_REL
 * 		Relocateable object file.
 * @li ET_EXEC
 * 		Executable.
 * @li ET_DYN
 * 		Shared object.
 * @li ET_CORE
 * 		Core.
 *
 * @param  melf [in] The melf context.
 * @param  type [in] The type to use.
 */
void melf_elfSetType(MELF *melf, Elf32_Half type);
/**
 * Gets the type of binary associated with the context.
 *
 * @param  melf [in] The melf context.
 * @return The type of binary.
 */
Elf32_Half melf_elfGetType(MELF *melf);

/**
 * Sets the machine the binary is designed for (e.g. EM_386)
 *
 * @param  melf    [in] The melf context.
 * @param  machine [in] The type of machine.
 */
void melf_elfSetMachine(MELF *melf, Elf32_Half machine);
/**
 * Get the machine the binary is desgined for.
 *
 * @param  melf [in] The melf context.
 * @return The type of machine.
 */
Elf32_Half melf_elfGetMachine(MELF *melf);

/**
 * Sets the ELF version. (e.g. EV_CURRENT)
 *
 * @param  melf    [in] The melf context.
 * @param  version [in] The version.
 */
void melf_elfSetVersion(MELF *melf, Elf32_Word version);
/**
 * Gets the ELF version.
 *
 * @param  melf [in] The melf context.
 * @return The ELF version.
 */
Elf32_Word melf_elfGetVersion(MELF *melf);

/**
 * Sets the entry point virtual address.
 *
 * @param  melf  [in] The melf context.
 * @param  entry [in] The entry point virtual address.
 */
void melf_elfSetEntry(MELF *melf, Elf32_Addr entry);
/**
 * Gets the entry point virtual address.
 *
 * @param  melf [in] The melf context.
 * @return The entry point virtual address.
 */
Elf32_Addr melf_elfGetEntry(MELF *melf);

/**
 * Sets the program header file offset.
 *
 * @param  melf   [in] The melf context.
 * @param  offset [in] The file offset for the program header.
 */
void melf_elfSetProgramHeaderOffset(MELF *melf, Elf32_Off offset);
/**
 * Gets the program header offset.
 *
 * @param  melf [in] The melf context.
 * @return The offset of the program header table.
 */
Elf32_Off melf_elfGetProgramHeaderOffset(MELF *melf);

/**
 * Sets the section header offset.
 *
 * @param  melf   [in] The melf context.
 * @param  offset [in] The offset of the section header table.
 */
void melf_elfSetSectionHeaderOffset(MELF *melf, Elf32_Off offset);
/**
 * Gets the section header offset.
 *
 * @param  melf [in] The melf context.
 * @return The offset of the section header table.
 */
Elf32_Off melf_elfGetSectionHeaderOffset(MELF *melf);

/**
 * Sets the number of program headers.
 *
 * @param  melf  [in] The melf context.
 * @param  count [in] The number of program headers.
 */
void melf_elfSetProgramHeaderCount(MELF *melf, Elf32_Half count);
/**
 * Gets the number of program headers.
 *
 * @param  melf [in] The melf context.
 * @return The number of program headers.
 */
Elf32_Half melf_elfGetProgramHeaderCount(MELF *melf);

/**
 * Sets the number of section headers.
 *
 * @param  melf  [in] The melf context.
 * @param  count [in] The number of section headers.
 */
void melf_elfSetSectionHeaderCount(MELF *melf, Elf32_Half count);
/**
 * Gets the number of section headers.
 *
 * @param  melf [in] The melf context.
 * @return The number of section headers.
 */
Elf32_Half melf_elfGetSectionHeaderCount(MELF *melf);

/**
 * Sets the index of the string table for section headers.
 *
 * @param  melf  [in] The melf context.
 * @param  index [in] The index to the string table header for section headers.
 */
void melf_elfSetStringTableIndex(MELF *melf, Elf32_Half index);
/**
 * Gets the index of the string table for section headers.
 *
 * @param  melf [in] The melf context.
 * @return The index to the string table header for section headers.
 */
Elf32_Half melf_elfGetStringTableIndex(MELF *melf);

/**
 * @}
 */

// Section functions

/**
 * @defgroup sections Section Headers
 * @ingroup  melf
 *
 * @{
 */

/**
 * Inserts a new section in the beginning.
 *
 * @param  melf [in] The melf context.
 * @return On success, a new blank section is returned.
 */
ELF_SPEC_HEADER *melf_sectionInsert(MELF *melf);
/**
 * Adds a new section.
 *
 * @param  melf [in] The melf context.
 * @return On success, a new blank section is returned.
 */
ELF_SPEC_HEADER *melf_sectionAdd(MELF *melf);
/**
 * Gets an enumerator for the section header table.
 *
 * @param  melf [in] The melf context.
 * @return On success, a pointer to the first entry in the section enumeration is returned, otherwise NULL is returned.
 */
ELF_SPEC_HEADER *melf_sectionGetEnum(MELF *melf);
/**
 * Gets the next entry in the section header enumeration.
 *
 * @param  melf [in] The melf context.
 * @param  en   [in] The current enumeration pointer.
 * @return The next header in the enumeration.
 */
ELF_SPEC_HEADER *melf_sectionEnumNext(MELF *melf, ELF_SPEC_HEADER *en);
/**
 * Gets the previous entry in the section header enumeration.
 *
 * @param  melf [in] The melf context.
 * @param  en   [in] The current enumeration pointer.
 * @return The previous header in the enumeration.
 */
ELF_SPEC_HEADER *melf_sectionEnumPrev(MELF *melf, ELF_SPEC_HEADER *en);

/**
 * Finds the first section header of a given type (e.g. SHT_NOTE)
 *
 * @param  melf [in] The melf context.
 * @param  type [in] The type to search for.
 * @return If a matching section is found a valid pointer will be returned, otherwise NULL is returned.
 */
ELF_SPEC_HEADER *melf_sectionFindType(MELF *melf, unsigned long type);
/**
 * Finds a section that is at the given index.
 *
 * @param  melf  [in] The melf context.
 * @param  index [in] The index to find a section at.
 * @return If a header exists at the provided index a valid pointer will be returned, otherwise NULL is returned.
 */
ELF_SPEC_HEADER *melf_sectionFindIndex(MELF *melf, unsigned long index);
/**
 * Finds the first section with a given name.
 *
 * @param  melf [in] The melf context.
 * @param  name [in] The name of the section to search for.
 * @return If a header exists with the provided name a valid pointer will be returned, otherwise NULL is returned.
 */
ELF_SPEC_HEADER *melf_sectionFindName(MELF *melf, const char *name);

/**
 * Sets the arbitrary content for the given section.
 *
 * @param  melf          [in] The melf context.
 * @param  section       [in] The section to operate on.
 * @param  content       [in] The raw content to set.  This parameter can be NULL.
 * @param  contentLength [in] The length of the raw content.  0 for no content.
 */
void melf_sectionSetContent(MELF *melf, ELF_SPEC_HEADER *section, void *content, unsigned long contentLength);
/**
 * Gets the raw content for a given section.
 *
 * @param  melf    [in] The melf context.
 * @param  section [in] The section to retrieve the content of.
 * @return If the specified section is valid and has content, a valid pointer is returned.  Otherwise, NULL is returned.
 */
void *melf_sectionGetContent(MELF *melf, ELF_SPEC_HEADER *section);

/**
 * Sets the name of a section.  If a string table does not exist for section headers then one 
 * is created, otherwise the existing one is used.
 *
 * @param  melf [in] The melf context.
 * @param  section [in] The section to operate on.
 * @param  name [in] The name to set the section to.
 */
void melf_sectionSetName(MELF *melf, ELF_SPEC_HEADER *section, const char *name);
/**
 * Gets the name of the section.
 *
 * @param  melf    [in] The melf context.
 * @param  section [in] The section to get the name of.
 * @return If the section has a name a valid pointer is returned.  Otherwise, NULL is returned.
 */
const char *melf_sectionGetName(MELF *melf, ELF_SPEC_HEADER *section);

/**
 * Sets the specified section to a given type. (e.g. SHT_SYMTAB, SHT_STRTAB)
 *
 * The type can be one of the following standard types:
 *
 * @li SHT_NULL
 * 		No type
 * @li SHT_PROGBITS
 * 		Program data.
 * @li SHT_SYMTAB
 * 		Symbol table.
 * @li SHT_STRTAB
 * 		String table.
 * @li SHT_RELA
 * 		Relocation entries with addends.
 * @li SHT_HASH
 * 		Symbol hash table.
 * @li SHT_DYNAMIC
 * 		Dynamic linking information.
 * @li SHT_NOTE
 * 		Notes
 * @li SHT_NOBITS
 * 		Program space with no data.
 * @li SHT_REL
 * 		Relocation entries with no addends.
 * @li SHT_DYNSYM
 * 		Dynamic linker symbol table.
 *
 * There are more acceptable types, but these are the standard set.
 *
 * @param  melf    [in] The melf context.
 * @param  section [in] The section to operate on.
 * @param  type    [in] The type to set the section to.
 */
void melf_sectionSetType(MELF *melf, ELF_SPEC_HEADER *section, unsigned long type);
/**
 * Gets the section type of a given section.
 *
 * @param  melf    [in] The melf context.
 * @param  section [in] The section to get the type of.
 * @return The section type.
 */
unsigned long melf_sectionGetType(MELF *melf, ELF_SPEC_HEADER *section);

/**
 * Sets the virtual address associated with the section.
 *
 * @param  melf    [in] The melf context.
 * @param  section [in] The section to operate on.
 * @param  addr    [in] The virtual address.
 */
void melf_sectionSetAddress(MELF *melf, ELF_SPEC_HEADER *section, Elf32_Addr addr);
/**
 * Gets the virtual address associated with a section.
 *
 * @param  melf    [in] The melf context.
 * @param  section [in] The section to operate on.
 * @return The virtual address associated with the section.
 */
Elf32_Addr melf_sectionGetAddress(MELF *melf, ELF_SPEC_HEADER *section);

/**
 * Set the flags on a given section.
 *
 * Flags can be one or more of the following:
 *
 * @li SHF_WRITE
 * 		Writable.
 * @li SHF_ALLOC
 * 		Occupies memory during execution.
 * @li SHF_EXECINSTR
 * 		Contains executable code.
 * @li SHF_MERGE
 * 		Might be merged.
 * @li SHF_STRINGS
 * 		Contains strings.
 * @li SHF_INFO_LINK
 * 		sh_info contains section index.
 * @li SHF_GROUP
 * 		Section is a member of a group.
 * @li SHF_TLS
 * 		Thread local storage.
 *
 * @param  melf    [in] The melf context.
 * @param  section [in] The section to set the flags on.
 * @param  flags   [in] The flags to set.
 */
void melf_sectionSetFlags(MELF *melf, ELF_SPEC_HEADER *section, Elf32_Word flags);
/**
 * Get the flags of a given section.
 *
 * @param  melf    [in] The melf context.
 * @param  section [in] The section to get the flags of.
 */
Elf32_Word melf_sectionGetFlags(MELF *melf, ELF_SPEC_HEADER *section);

/**
 * Set the size of an entry in the content for the section.
 *
 * @param  melf    [in] The melf context.
 * @param  section [in] The section to operate on.
 * @param  entsize [in] The size of a entry.
 */
void melf_sectionSetEntrySize(MELF *melf, ELF_SPEC_HEADER *section, Elf32_Word entsize);
/**
 * Get the size of an entry in the content for the section.
 *
 * @param  melf    [in] The melf context.
 * @param  section [in] The section to operate on.
 * @return The size of an entry.
 */
Elf32_Word melf_sectionGetEntrySize(MELF *melf, ELF_SPEC_HEADER *section);

/**
 * Get the index of a given section.
 *
 * @param  melf    [in] The melf context.
 * @param  section [in] The section to operate on.
 * @return The index of the section.
 */
unsigned long melf_sectionGetIndex(MELF *melf, ELF_SPEC_HEADER *section);

/**
 * Set the string table to associate with the section.  This is used for things like symbol tables
 * which tend to have their own string tables for symbol names.
 *
 * @param  melf        [in] The melf context.
 * @param  section     [in] The section to operate on.
 * @param  stringTable [in] The string table section to associate with.
 */
void melf_sectionSetStringTableHeader(MELF *melf, ELF_SPEC_HEADER *section, ELF_SPEC_HEADER *stringTable);
/**
 * Get the string table associated with a section.
 *
 * @param  melf    [in] The melf context.
 * @param  section [in] The section to operate on.
 * @return The string table section associated with the supplied section, if any.
 */
ELF_SPEC_HEADER *melf_sectionGetStringTableHeader(MELF *melf, ELF_SPEC_HEADER *section);

/**
 * Remove a given section by its identifier.
 *
 * @param  melf [in] The melf context.
 * @param  id   [in] The identifier of the section to remove.
 * @return 1 if successful.
 */
unsigned long melf_sectionRemove(MELF *melf, unsigned long id);

/**
 * @}
 */

/**
 * @defgroup programs Program Headers
 * @ingroup  melf
 *
 * @{
 */

/**
 * Adds a new program header.
 *
 * @param  melf [in] The melf context.
 * @return On success, a new blank program  headeris returned.
 */
ELF_SPEC_HEADER *melf_programAdd(MELF *melf);
/**
 * Gets an enumerator for the program header table.
 *
 * @param  melf [in] The melf context.
 * @return On success, a pointer to the first entry in the program enumeration is returned, otherwise NULL is returned.
 */
ELF_SPEC_HEADER *melf_programGetEnum(MELF *melf);
/**
 * Gets the next entry in the program header enumeration.
 *
 * @param  melf [in] The melf context.
 * @param  en   [in] The current enumeration pointer.
 * @return The next header in the enumeration.
 */
ELF_SPEC_HEADER *melf_programEnumNext(MELF *melf, ELF_SPEC_HEADER *en);
/**
 * Gets the previous entry in the program header enumeration.
 *
 * @param  melf [in] The melf context.
 * @param  en   [in] The current enumeration pointer.
 * @return The previous header in the enumeration.
 */
ELF_SPEC_HEADER *melf_programEnumPrev(MELF *melf, ELF_SPEC_HEADER *en);

/**
 * Set the program header type.
 *
 * type can be one of the following:
 *
 * @li PT_LOAD
 * 		Loadable segment.
 * @li PT_DYNAMIC
 * 		Dynamic linking information.
 * @li PT_INTERP
 * 		Program interpreter.
 * @li PT_NOTE
 * 		Auxiliary information.
 * @li PT_PHDR
 * 		Program header table.
 * @li PT_TLS
 * 		Thread-local storage.
 *
 * @param  melf    [in] The melf context.
 * @param  program [in] The program header to operate on.
 * @param  type    [in] The type to set it to.
 */
void melf_programSetType(MELF *melf, ELF_SPEC_HEADER *program, Elf32_Word type);
/**
 * Gets the type of a program header.
 *
 * @param  melf    [in] The melf context.
 * @param  program [in] The program header to operate on.
 * @return The type of a program header.
 */
Elf32_Word melf_programGetType(MELF *melf, ELF_SPEC_HEADER *program);

/**
 * Sets the virtual address associated with a program header.
 *
 * @param  melf    [in] The melf context.
 * @param  program [in] The program header to operate on.
 * @param  addr    [in] The virtual address to set to.
 */
void melf_programSetVirtualAddress(MELF *melf, ELF_SPEC_HEADER *program, Elf32_Addr addr);
/**
 * Gets the virtual address associated with a program header.
 *
 * @param  melf    [in] The melf context.
 * @param  program [in] The program header to operate on.
 * @return The virtual address.
 */
Elf32_Addr melf_programGetVirtualAddress(MELF *melf, ELF_SPEC_HEADER *program);

/**
 * Sets the physical address associated with a program header.
 *
 * @param  melf    [in] The melf context.
 * @param  program [in] The program header to operate on.
 * @param  addr    [in] The physical address to set to.
 */
void melf_programSetPhysicalAddress(MELF *melf, ELF_SPEC_HEADER *program, Elf32_Addr addr);
/**
 * Gets the physical address associated with a program header.
 *
 * @param  melf    [in] The melf context.
 * @param  program [in] The program header to operate on.
 * @return The physical address.
 */
Elf32_Addr melf_programGetPhysicalAddress(MELF *melf, ELF_SPEC_HEADER *program);

/**
 * Sets the virtual size of the program segment.
 *
 * @param  melf    [in] The melf context.
 * @param  program [in] The program header to operate on.
 * @param  size    [in] The virtual size.
 */
void melf_programSetVirtualSize(MELF *melf, ELF_SPEC_HEADER *program, Elf32_Word size);
/**
 * Gets the virtual size of the program segment.
 *
 * @param  melf    [in] The melf context.
 * @param  program [in] The program header to operate on.
 * @return The virtual size of the program segment.
 */
Elf32_Word melf_programGetVirtualSize(MELF *melf, ELF_SPEC_HEADER *program);

/**
 * Sets the physical size of the program segment.
 *
 * @param  melf    [in] The melf context.
 * @param  program [in] The program header to operate on.
 * @param  size    [in] The physical size of the program segment.
 */
void melf_programSetPhysicalSize(MELF *melf, ELF_SPEC_HEADER *program, Elf32_Word size);
/**
 * Gets the physical size of the program segment.
 *
 * @param  melf    [in] The melf context.
 * @param  program [in] The program header to operate on.
 * @return The physical size of the program segment.
 */
Elf32_Word melf_programGetPhysicalSize(MELF *melf, ELF_SPEC_HEADER *program);

/**
 * Sets the flags on the program header.
 *
 * flags can be one or more of the following:
 *
 * @li PF_R
 * 		Readable.
 * @li PF_W
 * 		Writable.
 * @li PF_X
 * 		Executable.
 *
 * @param  melf    [in] The melf context.
 * @param  program [in] The program header to operate on.
 * @param  flags   [in] The flags to set.
 */
void melf_programSetFlags(MELF *melf, ELF_SPEC_HEADER *program, Elf32_Word flags);
/**
 * Gets the flags associated with a program header.
 *
 * @param  melf    [in] The melf context.
 * @param  program [in] The program header to operate on.
 * @return The program header flags.
 */
Elf32_Word melf_programGetFlags(MELF *melf, ELF_SPEC_HEADER *program);

/**
 * Removes a program header of a given identifier.
 *
 * @param  melf [in] The melf context.
 * @param  id   [in] The identifier of the program header to be removed.
 * @return 1 on success.
 */
unsigned long melf_programRemove(MELF *melf, unsigned long id);

/**
 * @}
 */

/**
 * @defgroup sect_strings String Table
 * @ingroup  sections
 *
 * @{
 */

/**
 * Creates a new string table section with the specified name.  If the name 
 * is NULL, the name for the new section will not be set.
 *
 * @param  melf [in] The melf context.
 * @param  name [in] The name of the string table.  This can be NULL.
 * @return On success an initialized string table section header is returned.  Otherwise, NULL is returned.
 */
ELF_SPEC_HEADER *melf_stringTableCreate(MELF *melf, const char *name);

/**
 * Sets a string in the string table.  If the name exists in the string table its index will be 
 * re-used.  Otherwise, it is appended to the end.
 *
 * @param  melf        [in] The melf context.
 * @param  stringTable [in] The string table to operate on.
 * @param  name        [in] The name to set.
 * @return The index to the name in the string table content.
 */
unsigned long melf_stringTableSetString(MELF *melf, ELF_SPEC_HEADER *stringTable, const char *name);
/**
 * Gets the string value at the specified index in the string table.
 *
 * @param  melf        [in] The melf context.
 * @param  stringTable [in] The string table to operate on.
 * @param  index       [in] The index to get the string at.
 * @return A pointer to a valid string on success, otherwise NULL.
 */
const char *melf_stringTableGetString(MELF *melf, ELF_SPEC_HEADER *stringTable, unsigned long index);

/**
 * @}
 */

/**
 * @defgroup sect_dynamic Dynamic
 * @ingroup  sections
 *
 * @{
 */

/**
 * Creates and initialize a dynamic section header.
 *
 * @param  melf [in] The melf context.
 * @return On success, an initialized dynamic section header is returned.  Otherwise, NULL is returned.
 */
ELF_SPEC_HEADER *melf_dynamicCreate(MELF *melf);

/**
 * Adds a tag to the dynamic section.
 *
 * tag can be one of the following:
 *
 * @li DT_NULL
 * 		Blank entry.
 * @li DT_NEEDED
 * 		Name of a required dynamic library.
 * @li DT_PLTRELSZ
 * 		Size in bytes of the PLT relocs.
 * @li DT_PLTGOT
 * 		Processor defined value.
 * @li DT_HASH
 * 		Address of the symbol table hash.
 * @li DT_STRTAB
 * 		Address of the string table.
 * @li DT_SYMTAB
 * 		Address of the symbol table.
 * @li DT_RELA
 * 		Address of the rela relocs.
 * @li DT_RELASZ
 * 		Size of the rela relocs.
 * @li DT_RELAENT
 * 		Size of a rela entry.
 * @li DT_STRSZ
 * 		Size of the sring table.
 * @li DT_SYMENT
 * 		Size of a symbol entry.
 * @li DT_INIT
 * 		Address of init function.
 * @li DT_FINI
 * 		Address of fini function.
 * @li DT_SONAME
 * 		Name of shared object.
 * @li DT_REL
 * 		Address of the rel relocs.
 * @li DT_RELSZ
 * 		Size of the rel relocs.
 * @li DT_RELENT
 * 		Size of a rel entry.
 * @li DT_PLTREL
 * 		Type of reloc in PLT.
 * @li DT_TEXTREL
 * 		Reloc might modify .text.
 * @li DT_JMPREL
 * 		Address of PLT relocs.
 * @li DT_RUNPATH
 * 		Library search path.
 * @li DT_FLAGS
 * 		Flags for object being loaded.
 * @li DT_ENCODING
 * 		Start of encoding range.
 *
 * There are a few more tags that are not specified here.
 *
 * @param  melf    [in] The melf context.
 * @param  dynamic [in] The dynamic section to operate on.
 * @param  tag     [in] The tag to set.
 * @param  val     [in] The arbitrary value associated with the tag.
 * @return On succes, a new dynamic entry structure is returned.  Otherwise, NULL is returned.
 */
Elf32_Dyn *melf_dynamicAddTag(MELF *melf, ELF_SPEC_HEADER *dynamic, Elf32_Sword tag, Elf32_Word val);
/**
 * Removes all instances of a specified tag.
 *
 * @param  melf    [in] The melf context.
 * @param  dynamic [in] The dynamic section to operate on.
 * @param  tag     [in] The tag to remove.
 * @return The number of instances removed.
 */
unsigned long melf_dynamicRemoveTag(MELF *melf, ELF_SPEC_HEADER *dynamic, Elf32_Sword tag);
/**
 * Removes an entry at a specific index.  Indexes start at 0.
 *
 * @param  melf    [in] The melf context.
 * @param  dynamic [in] The dynamic section to operate on.
 * @param  index   [in] The index to remove.
 * @return 1 if successful.
 */
unsigned long melf_dynamicRemoveIndex(MELF *melf, ELF_SPEC_HEADER *dynamic, unsigned long index);
/**
 * Gets the first instance of a specified tag.
 *
 * @param  melf    [in] The melf context.
 * @param  dynamic [in] The dynamic section to operate on.
 * @param  tag     [in] The tag to get.
 * @return If an instance of the given tag is found a valid pointer is returned.  Otherwise, NULL is returned.
 */
Elf32_Dyn *melf_dynamicGetTag(MELF *melf, ELF_SPEC_HEADER *dynamic, Elf32_Sword tag);
/**
 * Gets the dynamic entry at a given index.  Indexes start at 0.
 *
 * @param  melf    [in] The melf context.
 * @param  dynamic [in] The dynamic section to operate on.
 * @param  index   [in] The index to get the dynamic entry of.
 * @return A valid pointer to a dynamic entry if the index is valid, otherwise NULL.
 */
Elf32_Dyn *melf_dynamicGetIndex(MELF *melf, ELF_SPEC_HEADER *dynamic, unsigned long index);
/**
 * Attempts to update a given tag if one exists, otherwise a new one is added.
 *
 * @param  melf    [in] The melf context.
 * @param  dynamic [in] The dynamic section to operate on.
 * @param  tag     [in] The tag to set.
 * @param  val     [in] The arbitrary value of a given tag.
 * @return 1 on success.
 */
unsigned long melf_dynamicSetTag(MELF *melf, ELF_SPEC_HEADER *dynamic, Elf32_Sword tag, Elf32_Word val);
/**
 * Sets the value of an entry at a specified index.
 *
 * @param  melf    [in] The melf context.
 * @param  dynamic [in] The dynamic section to operate on.
 * @param  index   [in] The index to operate on.
 * @param  val     [in] The arbitrary value.
 * @return 1 on success.
 */
unsigned long melf_dynamicSetIndex(MELF *melf, ELF_SPEC_HEADER *dynamic, unsigned long index, Elf32_Word val);

/**
 * @}
 */

/**
 * @defgroup sect_note Note
 * @ingroup  sections
 *
 * @{
 */

/**
 * Creates a note section with the provided name, optionally creating a program header for the note section.
 *
 * @param  melf                [in] The melf context.
 * @param  name                [in] The name of the section.  This can be NULL.
 * @param  createProgramHeader [in] 1 if a PT_NOTE program header is to be made, 0 if not.
 * @return On success, an initialized note section header is returned.  Otherwise, NULL is returned.
 */
ELF_SPEC_HEADER *melf_noteCreate(MELF *melf, const char *name, unsigned long createProgramHeader);

/**
 * Adds an entry to the note section.
 *
 * type can be one of the following for object files:
 *
 * @li NT_VERSION
 * 		Contains a version string.
 *
 * type can be one of the following for core files:
 *
 * @li NT_PRSTATUS
 * 		Contains a copy of prstatus struct.
 * @li NT_FPREGSET
 * 		Contains copy of fpregset struct.
 * @li NT_PRPSINFO
 * 		Contains copy of prpsinfo struct.
 * @li NT_PRXREG
 * 		Contains copy of prxregset struct.
 * @li NT_PLATFORM
 * 		String from sysinfo(SI_PLATFORM).
 * @li NT_AUXV
 * 		Contains copy of auxv array.
 * @li NT_GWINDOWS
 * 		Contains copy of gwindows struct.
 * @li NT_PSTATUS
 * 		Contains copy of pstatus struct.
 * @li NT_PSINFO
 * 		Contains copy of psinfo struct.
 * @li NT_PRCRED
 * 		Contains copy of prcred struct.
 * @li NT_UTSNAME
 * 		Contains copy of utsname struct.
 * @li NT_LWPSTATUS
 * 		Contains copy of lwpstatus struct.
 * @li NT_LWPSINFO
 * 		Contains copy of lwpinfo struct.
 * @li NT_PRFPXREG
 * 		Contains copy of fprxregset struct
 *
 * @param  melf       [in] The melf context.
 * @param  note       [in] The note section to operate on.
 * @param  type       [in] The type of note.
 * @param  name       [in] The name associated with the type.
 * @param  desc       [in] The desc associated with the type.
 * @param  descLength [in] The length of the desc.
 */
Elf32_Nhdr *melf_noteAdd(MELF *melf, ELF_SPEC_HEADER *note, Elf32_Word type, const char *name, unsigned char *desc, unsigned long descLength);
/**
 * Enumerates the note entries at a given index.  Indexes start at 0.
 *
 * @param  melf  [in] The melf context.
 * @param  note  [in] The note section to operate on.
 * @param  index [in] The index to enumerate at.
 * @return If the index is valid, a valid pointer to a note entry is returned.  Otherwise, NULL is returned.
 */
Elf32_Nhdr *melf_noteEnum(MELF *melf, ELF_SPEC_HEADER *note, unsigned long index);
/**
 * Removes a note entry.
 *
 * @param  melf [in] The melf context.
 * @param  note [in] The note section to operate on.
 * @param  item [in] The entry to remove.
 * @return 1 on success.
 */
unsigned long melf_noteRemove(MELF *melf, ELF_SPEC_HEADER *note, Elf32_Nhdr *item);

/**
 * Gets the type associated with a given note entry.
 *
 * @param  melf [in] The melf context.
 * @param  note [in] The note section to operate on.
 * @param  item [in] The entry to get the type of.
 * @return The type.
 */
unsigned long melf_noteGetType(MELF *melf, ELF_SPEC_HEADER *note, Elf32_Nhdr *item);
/**
 *
 * @param  melf [in] The melf context.
 * @param  note [in] The note section to operate on.
 * @param  item [in] The entry to get the name of.
 * @return The name.
 */
const char *melf_noteGetName(MELF *melf, ELF_SPEC_HEADER *note, Elf32_Nhdr *item);
/**
 *
 * @param  melf [in] The melf context.
 * @param  note [in] The note section to operate on.
 * @param  item [in] The entry to get the desc of.
 * @return The desc.
 */
unsigned char *melf_noteGetDesc(MELF *melf, ELF_SPEC_HEADER *note, Elf32_Nhdr *item);

/**
 * @}
 */

/**
 * @defgroup sect_symboltable Symbol Table
 * @ingroup  sections
 *
 * @{
 */

/**
 * Creates a symbol table with the specified name.
 *
 * @param  melf [in] The melf context.
 * @param  name [in] The name of the symbol table.  This can be NULL.
 * @return On success, an initialized symbol table section is returned.  Otherwise, NULL is returned.
 */
ELF_SPEC_HEADER *melf_symbolTableCreate(MELF *melf, const char *name);

/**
 * Adds a new symbol with the given name to the symbol table.
 *
 * @param  melf     [in] The melf context.
 * @param  symTable [in] The symbol table to operate on.
 * @param  name     [in] The name of the symbol.  This can be NULL.
 */
Elf32_Sym *melf_symbolTableAddSymbol(MELF *melf, ELF_SPEC_HEADER *symTable, const char *name);
/**
 * Enumerates the symbol table at the given index.  Indexes start at 0.
 *
 * @param  melf     [in] The melf context.
 * @param  symTable [in] The symbol table to operate on.
 * @param  index    [in] The index to enumerate at.
 * @return If the index is valid, a valid pointer to a symbol will be returned.  Otherwise, NULL is returned.
 */
Elf32_Sym *melf_symbolTableEnum(MELF *melf, ELF_SPEC_HEADER *symTable, unsigned long index);
/**
 * Removes a given symbol.
 *
 * @param  melf     [in] The melf context.
 * @param  symTable [in] The symbol table to operate on.
 * @param  symbol   [in] The symbol to remove.
 * @return 1 on success.
 */
unsigned long melf_symbolTableRemoveSymbol(MELF *melf, ELF_SPEC_HEADER *symTable, Elf32_Sym *symbol);

/**
 * @}
 */

/**
 * @defgroup sect_symbols Symbols
 * @ingroup  sect_symboltable
 *
 * @{
 */

/**
 * Sets the name of a given symbol.
 *
 * @param  melf     [in] The melf context.
 * @param  symTable [in] The symbol table to operate on.
 * @param  sym      [in] The symbol to operate on.
 * @param  name     [in] The name to set it to.
 */
void melf_symbolSetName(MELF *melf, ELF_SPEC_HEADER *symTable, Elf32_Sym *sym, const char *name);
/**
 *
 * @param  melf     [in] The melf context.
 * @param  symTable [in] The symbol table to operate on.
 * @param  sym      [in] The symbol to operate on.
 * @return THe name of the symbol.
 */
const char *melf_symbolGetName(MELF *melf, ELF_SPEC_HEADER *symTable, Elf32_Sym *sym);

/**
 * Set the value of the sybmol.  This is typically the virtual address at which it is found in memory.
 *
 * @param  melf     [in] The melf context.
 * @param  symTable [in] The symbol table to operate on.
 * @param  sym      [in] The symbol to operate on.
 * @param  value    [in] The arbitrary value.
 */
void melf_symbolSetValue(MELF *melf, ELF_SPEC_HEADER *symTable, Elf32_Sym *sym, Elf32_Addr value);
/**
 * Gets the value associated with the symbol.
 *
 * @param  melf     [in] The melf context.
 * @param  symTable [in] The symbol table to operate on.
 * @param  sym      [in] The symbol to operate on.
 * @return The value of the symbol.
 */
Elf32_Addr melf_symbolGetValue(MELF *melf, ELF_SPEC_HEADER *symTable, Elf32_Sym *sym);

/**
 * Sets the size of the symbol in virtual memory.
 *
 * @param  melf     [in] The melf context.
 * @param  symTable [in] The symbol table to operate on.
 * @param  sym      [in] The symbol to operate on.
 * @param  size     [in] The size of the symbol in virtual memory.
 */
void melf_symbolSetSize(MELF *melf, ELF_SPEC_HEADER *symTable, Elf32_Sym *sym, Elf32_Word size);
/**
 * Gets the size of the symbol in virtual memory.
 *
 * @param  melf     [in] The melf context.
 * @param  symTable [in] The symbol table to operate on.
 * @param  sym      [in] The symbol to operate on.
 * @return The size of the symbol in virtual memory.
 */
Elf32_Word melf_symbolGetSize(MELF *melf, ELF_SPEC_HEADER *symTable, Elf32_Sym *sym);

/**
 * Sets the binding information of the symbol.
 *
 * binding can be one of the following:
 *
 * @li STB_LOCAL
 * 		Local symbol.
 * @li STB_GLOBAL
 * 		Global symbol.
 * @li STB_WEAK
 * 		Weak symbol.
 *
 * @param  melf     [in] The melf context.
 * @param  symTable [in] The symbol table to operate on.
 * @param  sym      [in] The symbol to operate on.
 * @param  binding  [in] The symbol binding information.
 */
void melf_symbolSetBinding(MELF *melf, ELF_SPEC_HEADER *symTable, Elf32_Sym *sym, unsigned char binding);
/**
 * Gets the symbol binding information.
 *
 * @param  melf     [in] The melf context.
 * @param  symTable [in] The symbol table to operate on.
 * @param  sym      [in] The symbol to operate on.
 * @return Binding information.
 */
unsigned char melf_symbolGetBinding(MELF *melf, ELF_SPEC_HEADER *symTable, Elf32_Sym *sym);

/**
 * Sets the symbol type.
 *
 * type can be one of the following:
 *
 * @li STT_NOTYPE
 * 		No type.
 * @li STT_OBJECT
 * 		Symbol is a data object.
 * @li STT_FUNC
 * 		Symbol is a function.
 * @li STT_SECTION
 * 		Symbol associated with a section.
 * @li STT_FILE
 * 		Symbol's name is a file name.
 * @li STT_COMMON
 * 		Symbol is a common data object.
 *
 * @param  melf     [in] The melf context.
 * @param  symTable [in] The symbol table to operate on.
 * @param  sym      [in] The symbol to operate on.
 * @param  type     [in] The type of the symbol.
 */
void melf_symbolSetType(MELF *melf, ELF_SPEC_HEADER *symTable, Elf32_Sym *sym, unsigned char type);
/**
 * Gets the type of the symbol.
 *
 * @param  melf     [in] The melf context.
 * @param  symTable [in] The symbol table to operate on.
 * @param  sym      [in] The symbol to operate on.
 * @return The symbol type.
 */
unsigned char melf_symbolGetType(MELF *melf, ELF_SPEC_HEADER *symTable, Elf32_Sym *sym);

/**
 * Sets the section index of the symbol.
 *
 * @param  melf     [in] The melf context.
 * @param  symTable [in] The symbol table to operate on.
 * @param  sym      [in] The symbol to operate on.
 * @param  shndx    [in] The section index.
 */
void melf_symbolSetSectionIndex(MELF *melf, ELF_SPEC_HEADER *symTable, Elf32_Sym *sym, Elf32_Half shndx);
/**
 * Gets the section index of the symbol.
 *
 * @param  melf     [in] The melf context.
 * @param  symTable [in] The symbol table to operate on.
 * @param  sym      [in] The symbol to operate on.
 * @return The section index.
 */
Elf32_Half melf_symbolGetSectionIndex(MELF *melf, ELF_SPEC_HEADER *symTable, Elf32_Sym *sym);

/**
 * @}
 */

/**
 * @defgroup elfres ELF Resources
 * @ingroup  melf
 *
 * @{
 */

/**
 * Enumeration of resource types
 *
 * @short Elf resource types
 */
typedef enum _Elf32_ResType {
	/**
	 * Unknown resource
	 */
	ELF_RES_TYPE_UNKNOWN = 0,
	/**
	 * String resource
	 */
	ELF_RES_TYPE_STRING  = 1,
	/**
	 * Binary resource
	 */
	ELF_RES_TYPE_BINARY  = 2,
} Elf32_ResType;

/**
 * Elf resource object for an individual resource.
 *
 * @short Elf resource
 */
typedef struct _Elf32_Res {

	// Stored on disk:
	struct _Elf32_Res_Header {

		/**
		 * The length of the resource, including the header.
		 */
		unsigned long length;
		/**
		 * The type of the resource.
		 */
		Elf32_ResType type;
		/**
		 * The resource identifier.
		 */
		unsigned long identifier;
	} header;

	/**
	 * The resource data
	 */
	void          *data;	

	// Not stored on disk, internal use only:
	/**
	 * The index of the resource
	 */
	unsigned long index;
	/**
	 * The offset of the resource
	 */
	unsigned long offset;

} Elf32_Res;

/**
 * Opens an existing resource section, if one exists.
 *
 * @param  melf [in] The melf context.
 * @return On success, the corresponding section is returned, otherwise NULL.
 */
ELF_SPEC_HEADER *melf_resOpen(MELF *melf);
/**
 * Creates a new resource section, or opens an existing one if one exists.
 *
 * @param  melf [in] The melf context.
 * @return On success, the corresponding section is returned, otherwise NULL.
 */
ELF_SPEC_HEADER *melf_resCreate(MELF *melf);
/**
 * Enumerates the resources in a given resource section.
 *
 * @param  melf     [in]  The melf context.
 * @param  resTable [in]  The resource table section.
 * @param  index    [in]  The current enumeration index.
 * @param  res      [out] The buffer to hold the resource.
 * @return If there is a resource at the given index, 1 is returned, otherwise 0 is returned.
 */
unsigned char melf_resEnum(MELF *melf, ELF_SPEC_HEADER *resTable, unsigned long index, Elf32_Res *res);
/**
 * Gets a resource entry by a specified type.
 *
 * @param  melf     [in]  The melf context.
 * @param  resTable [in]  The resource table section.
 * @param  type     [in]  The type to search for.
 * @param  res      [out] The buffer to hold the resource.
 * @return On success, 1 is returned, otherwise 0 is returned.
 */
unsigned char melf_resGetType(MELF *melf, ELF_SPEC_HEADER *resTable, Elf32_ResType type, Elf32_Res *res);
/**
 * Gets a resource entry by a specified identifier.
 *
 * @param  melf     [in]  The melf context.
 * @param  resTable [in]  The resource table section.
 * @param  id       [in]  The identifier to search for.
 * @param  res      [out] The buffer to hold the resource.
 * @return On success, 1 is returned, otherwise 0 is returned.
 */
unsigned char melf_resGetId(MELF *melf, ELF_SPEC_HEADER *resTable, unsigned long id, Elf32_Res *res);
/**
 * Adds a new resource to the resource table.  Resource identifiers must be unique.
 *
 * @param  melf     [in]  The melf context.
 * @param  resTable [in]  The resource table section.
 * @param  type     [in]  The resource type.
 * @param  length   [in]  The length of the data buffer passed in.
 * @param  id       [in]  The identifier to associate this resource with.
 * @param  data     [in]  The arbitrary data.
 * @return On success, 1 is returned, otherwise 0 is returned.
 */
unsigned char melf_resAdd(MELF *melf, ELF_SPEC_HEADER *resTable, Elf32_ResType type, unsigned long length, unsigned long id, void *data);
/**
 * Updates a resource to the resource table.  Resource identifiers must be unique.
 * If the resource does not exist it is created.
 *
 * @param  melf     [in]  The melf context.
 * @param  resTable [in]  The resource table section.
 * @param  type     [in]  The resource type.
 * @param  length   [in]  The length of the data buffer passed in.
 * @param  id       [in]  The identifier to associate this resource with.
 * @param  data     [in]  The arbitrary data.
 * @return On success, 1 is returned, otherwise 0 is returned.
 */
unsigned char melf_resUpdate(MELF *melf, ELF_SPEC_HEADER *resTable, Elf32_ResType type, unsigned long length, unsigned long id, void *data);
/**
 * Removes a resource to the resource table.  Resource identifiers must be unique.
 *
 * @param  melf     [in]  The melf context.
 * @param  resTable [in]  The resource table section.
 * @param  res      [in]  The resource to remove.
 * @return On success, 1 is returned, otherwise 0 is returned.
 */
unsigned char melf_resRemove(MELF *melf, ELF_SPEC_HEADER *resTable, Elf32_Res *res);
/**
 * Closes a resource table.  This currently has no operation.
 *
 * @param  melf     [in]  The melf context.
 * @param  resTable [in]  The resource table section.
 */
void melf_resClose(MELF *melf, ELF_SPEC_HEADER *resTable);

/**
 * @}
 */

#ifdef MELF_COMP
#include "melf_internal.h"
#endif

#endif
