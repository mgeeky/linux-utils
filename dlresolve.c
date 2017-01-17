/*
 * dlresolve utility aiming to quickly obtain libc library's path 
 * and selected symbol's address as well as it's offset from the 
 * beginning of loaded libc base address. Useful while crafting ASLR exploits, 
 * when we have to determine offset to the symbol.
 *
 * Compilation:
 *    $ gcc dlresolve.c -o dlresolve -ldl
 *
 * Mariusz B., 2017
**/

#include <dlfcn.h>
#include <stdio.h>
#include <stdint.h>
#include <strings.h>
#include <string.h>

int8_t fetch_libc_path_and_base(char *path, void** baseaddress) {

    FILE *f = fopen("/proc/self/maps", "r");
    char line[256];
    int8_t found = 0;

    while (!feof(f)) {
        memset(line, 0, sizeof(line));
        fgets(line, sizeof(line)-1, f);

        if (strstr(line, "/libc") != NULL && strstr(line, "r-xp") != NULL) {
            found = 1;
            break;
        }
    }

    if (!found) {
        fclose(f);
        return 0;
    }

    size_t pos = (size_t)(strstr(line, "-") - line);
    char base[20] = "0x";

    strncat(base, line, pos);
    void* baseaddr = NULL;

	if (sizeof(void*) == 4){
		sscanf(base, "%x", &baseaddr);
	} else {
		sscanf(base, "%llx", &baseaddr);
	}
    *((void**)baseaddress) = baseaddr;

    pos = (size_t)(rindex(line, ' ') - line + 1);
    strncpy(path, &line[pos], 255);
	char *p = index(path, '\n');
	*p = 0;
    
    fclose(f);
    return 1;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        printf("Usage: %s <symbol>\n", argv[0]);
        return 1;
    }

    void* libc_base;
    char libc_path[256] = {0};

    if(!fetch_libc_path_and_base(libc_path, &libc_base)) {
        fputs("[!] Could not fetch libc path and base address.", stderr);
        return 1;
    }

    printf("[+] libc comes from:\t\t%s\n", libc_path);
	printf("[+] libc loaded at:\t\t%p\n", libc_base);

    /*void *handle = dlopen(libc_path, RTLD_LAZY);*/
    void *handle = dlopen("libc.so.6", RTLD_LAZY);
    if(!handle) {
        fputs(dlerror(), stderr);
        return 1;
    }

    void *ptr = dlsym(handle, argv[1]);
    char *error;
    if ((error = dlerror()) != NULL) {
        fputs(error, stderr);
        return 1;
    }

	if (sizeof(void*) == 4) {
		printf("[+] %s located at:\t\t0x%08x\n", argv[1], (unsigned int)ptr);
	} else {
		printf("[+] %s located at:\t\t0x%08lx\n", argv[1], (unsigned long int)ptr);
	}

    printf("[+] Offset from libc base:\t0x%08x\n", (size_t)(ptr - libc_base));

    return 0;
}

