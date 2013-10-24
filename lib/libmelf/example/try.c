#include <stdio.h>

main(void) {
	char *p;
	printf("Enter address: ");
	scanf("%x", (int *)&p);
	printf("%s\n", p);
}
