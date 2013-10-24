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

/* Added by Deepak - insert a header in the beginning */
ELF_SPEC_HEADER *_melf_listPrepend(ELF_SPEC_HEADER_LIST *list, void *header, unsigned long headerLength, void *content, unsigned long contentLength)
{
	ELF_SPEC_HEADER *curr = (ELF_SPEC_HEADER *)malloc(sizeof(ELF_SPEC_HEADER));
	ELF_SPEC_HEADER *p;

	if (!curr)
		return 0;

	memset(curr, 0, sizeof(ELF_SPEC_HEADER));

	curr->next = list->head;
	list->head = curr;
	if (!(list->tail))
		list->tail = curr;
	curr->index = 0;
	curr->identifier = ++list->seq;
	/* increment index for all old sections */
	for (p = curr->next; p; p = p->next)
		(p->index)++;

	if (header)
		memcpy(&curr->spec, header, headerLength);

	if (content && contentLength)
	{
		if ((curr->content = malloc(curr->contentLength = contentLength)))
			memcpy(curr->content, content, contentLength);
	}


	list->length++;

	return curr;
}

ELF_SPEC_HEADER *_melf_listAppend(ELF_SPEC_HEADER_LIST *list, void *header, unsigned long headerLength, void *content, unsigned long contentLength)
{
	ELF_SPEC_HEADER *curr = (ELF_SPEC_HEADER *)malloc(sizeof(ELF_SPEC_HEADER));

	if (!curr)
		return 0;

	memset(curr, 0, sizeof(ELF_SPEC_HEADER));

	if (list->tail)
	{
		list->tail->next = curr;
		curr->prev       = list->tail;
	}
	else
		list->head = curr;

	curr->identifier = ++list->seq;
	curr->index      = list->length;

	if (header)
		memcpy(&curr->spec, header, headerLength);

	curr->contentLength = contentLength;
	if (contentLength && ((Elf32_Shdr *)header)->sh_type != SHT_NOBITS)
	{
		if ((curr->content = malloc(contentLength)))
			memcpy(curr->content, content, contentLength);
	}

	list->tail  = curr;

	list->length++;


	return curr;
}

unsigned long _melf_listRemove(ELF_SPEC_HEADER_LIST *list, unsigned long id)
{
	ELF_SPEC_HEADER *curr = NULL, *dec = NULL;
	unsigned long success = 0;

	for (curr = list->head; 
			curr; 
			curr = curr->next)
	{
		if (curr->identifier == id)
		{
			// Decrement indexes from this point
			dec = curr->next;

			if (curr->prev)
				curr->prev->next = curr->next;
			if (curr->next)
				curr->next->prev = curr->prev;
			if (curr == list->head)
				list->head = curr->next;
			if (curr == list->tail)
				list->tail = curr->prev;

			if (curr->content)
				free(curr->content);
			
			free(curr);
			
			list->length--;
		}
	}

	for (;
			dec;
			dec = dec->next)
		dec->index--;

	return success;
}

unsigned long _melf_listFlush(ELF_SPEC_HEADER_LIST *list)
{
	ELF_SPEC_HEADER *head = list->head, *next;

	while (head)
	{
		next = head->next;

		if (head->content)
			free(head->content);

		free(head);

		head = next;

		list->length--;
	}

	return 1;
}
