#ifdef _GNU_SOURCE
#include <stdlib.h>
#include <fcntl.h>
#define __USE_GNU 1
#include <dlfcn.h>



#define __USE_GNU 1



int printf(const char *arg1,...){
	int (*ac_printf)(const char *,...);
	char *inserted_symbol;
	ac_printf=(int (*)(const char *,...))dlsym(RTLD_NEXT,"printf");
	if(ac_printf==NULL){
	  printf("Could not find printf definition\n");
	  exit(1);
	}
	inserted_symbol=(char *)dlsym(RTLD_DEFAULT,"new_symbol_avijit");
	if(inserted_symbol==NULL){
	  (*ac_printf)("Could not find the inserted symbol \n");
	  (*ac_printf)("The string at 80471c8 is:%s\n",0x80471c8);
	  exit(1);
	}
	else{
	  (*ac_printf)("Addr of new_symbol_avijit is:%p\n",inserted_symbol);
	  (*ac_printf)("new_symbol_avijit is: %s\n",inserted_symbol);
	}
	return 1;
}

#endif
