#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <stdarg.h> 
#include <sys/stat.h>
#include <sys/ptrace.h>

#if defined(__LP64) || defined(_LP64)
#endif

#define MAX_MEMORY_REGIONS 256

typedef struct {
  uintptr_t start;
  uintptr_t stop;
  char *name;
  int readable;
} memory_region;

typedef struct {
  pid_t pid;
  uintptr_t start;
  uintptr_t stop;
  int verbose;
  int force;
  char *outdir;

  size_t numregions;
  memory_region regions[MAX_MEMORY_REGIONS];

} params;

extern char *optarg;
extern int optind, opterr, optopt;
extern int errno;

params g_params;
int g_attached;


void usage();
int parse_opts(int argc, char **argv);
void cleanup();
size_t fetch_proc_memory_maps(pid_t pid, memory_region* regions);
void hexdump(char *desc, void *addr, uintptr_t base, int len);
int dump(pid_t pid, uintptr_t start, uintptr_t stop, const char *outdir);
int dump_all(pid_t pid, const char *outdir);
