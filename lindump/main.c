#include "defs.h"

void error(const char *x, ...){
  va_list va;
  va_start(va, x);
  char buf[256];
  strcpy(buf, x);
  strcat(buf, "\n");
  vfprintf(stderr, buf, va);
  va_end(va);
}

void verbose(const char *x, ...){
  if (g_params.verbose && (g_params.outdir != NULL && 0 != strcmp(g_params.outdir, "-"))) {
    va_list va;
    va_start(va, x);
    char buf[256];
    strcpy(buf, x);
    strcat(buf, "\n");
    vfprintf(stderr, buf, va);
    va_end(va);
  }
}

void hexdump(char *desc, void *addr, uintptr_t base, int len) {
  size_t i;
  unsigned char buff[17];
  unsigned char *pc = (unsigned char*)addr;

  if (desc != NULL)
    printf ("%s:\n", desc);

  if (len <= 0)
    return;

  for (i = 0; i < len; i++) {
    if ((i % 16) == 0) {
      if (i != 0)
        printf ("  %s\n", buff);

      if(sizeof(void*) == 8) {
        printf ("  %016x ", i + base);
      } else {
        printf ("  %08x ", i + base);
      }
    }

    printf (" %02x", pc[i]);

    if ((pc[i] < 0x20) || (pc[i] > 0x7e))
      buff[i % 16] = '.';
    else
      buff[i % 16] = pc[i];

    buff[(i % 16) + 1] = '\0';
  }

  while ((i % 16) != 0) {
    printf ("   ");
    i++;
  }

  printf ("  %s\n", buff);
}

size_t process_read(pid_t pid, uintptr_t address, size_t len, void *dst ) {
  size_t iters = len / sizeof(void*);
  size_t read = 0;
  unsigned char *addr = (unsigned char*)address;
  unsigned char *out = (unsigned char*)dst;

  while (iters-- != 0) {
    long word = ptrace(PTRACE_PEEKTEXT, pid, addr, NULL);
    if (word == -1 && errno) {
      if (!g_params.force) {
        error("Reading process memory failed at PID:%d, address: 0x%lx", pid, addr);
        return read;
      }
      else {
        word = 0;
      }
    }

    *(long *)out = word;
    addr += sizeof(long);
    out += sizeof(long);
    read += sizeof(long);
  }

  return read;
}

int dump(pid_t pid, uintptr_t start, uintptr_t stop, const char *outdir) {

  if(stop - start == 0) {
    error("Nothing selected to be dumped. Empty region.");
    return 0;
  }

  if (start > stop) {
    error("Invalid region specified: start: 0x%lx, stop: 0x%lx\n",
          start, stop);
    return 0;
  }

  if((stop - start) % 4 != 0) {
    printf("Warning: Specified region: 0x%lx-0x%lx is not divisible by 4 - rounding it down\n", start, stop);
    stop &= ~4;
    verbose("Resulting in: 0x%lx-0x%lx\n", start, stop);
  }

  char filename[64];
  snprintf(filename, sizeof(filename), "dump%lx-%lx.bin", start, stop);

  const size_t size = stop - start;
  void *dumped = malloc(size);

  if(!dumped) {
    error("Could not allocate buffer for region dump. Size: %d\n", size);
    perror("malloc");
    return 0;
  }

  verbose("Dumping: 0x%lx-0x%lx (%d bytes)",
          start, stop, (stop-start));

  if (size != process_read(pid, start, size, dumped)) {
    error("Could not read requested ammount of memory.");
    free(dumped);
    return 0;
  }

  int ok = 1;
  if (outdir != NULL && 0 != strcmp(outdir, "-")) {
    char path[PATH_MAX];
    snprintf(path, PATH_MAX, "%s/%s", outdir, filename);

    printf("Writing dump to file: '%s'\n", path);
    FILE *f = fopen(path, "wb");
    if(f) {
      size_t written = fwrite(dumped, 1, size, f);
      if (written != size) {
        char buf[256];
        sprintf(buf,
                "fwrite failed while writing dump to file (%d out of %d)\n",
                written, size);
        error(buf);
        ok = 0;
      }
      fclose(f);
    }
    else {
      perror("fopen to dump memory region.");
      ok = 0;
    }
  }
  else if(outdir != NULL && !strcmp(outdir, "-")) {
    fwrite(dumped, 1, size, stdout);
  }
  else {
    hexdump(filename, dumped, start, size);
  }

  free(dumped);
  return ok;
}

int dump_all(pid_t pid, const char *outdir) {
  size_t i;
  size_t succeeds = 0;
  for(i = 0; i < g_params.numregions; i++) {
    if(!g_params.force && !g_params.regions[i].readable) {
      verbose("Region: 0x%lx-0x%lx is not readable, skipping.", 
              g_params.regions[i].start, g_params.regions[i].stop);
      continue;
    }
    if(!dump(pid, g_params.regions[i].start, g_params.regions[i].stop, outdir)) {
      if(!g_params.force) {
        error("Dumping of proc (%d) region 0x%lx-0x%lx failed. Proceeding...\n",
              pid, g_params.regions[i].start, g_params.regions[i].stop);
      }
    }
    else {
      succeeds++;
    }
  }
  return succeeds;
}

size_t fetch_proc_memory_maps(pid_t pid, memory_region* regions) {
  char path[18];
  snprintf(path, sizeof(path),"/proc/%ld/maps", g_params.pid);
  if ( access( path, F_OK) == -1) {
    error("There is no process with specified pid = %d", g_params.pid);
    return 0;
  }

  FILE *f = fopen(path, "r");
  if (!f) {
    perror("fopen");
    return 0;
  }

  g_params.numregions = 0;
  char *line = NULL;
  size_t len = 0;
  ssize_t read;

  size_t numregions = 0;
  const size_t max_regions = MAX_MEMORY_REGIONS;

  while(!feof(f)) {
    char buf[PATH_MAX + 128], perm[6], dev[8];
    char mapname[PATH_MAX] = {0};
    uintptr_t start = 0, stop = 0, size, inode, foo;

    if (numregions >= max_regions)
      break;

    if(fgets(buf, sizeof(buf), f) == 0)
      break;

    sscanf(buf, "%p-%p %4s %lx %5s %ld %s",
          &start, &stop, perm, &foo, dev, &inode, mapname);

    regions[numregions].start = start;
    regions[numregions].stop = stop;
    regions[numregions].readable = (perm[0] == 'r');

    size_t len = strlen(mapname);
    if ( len > PATH_MAX) {
      len = PATH_MAX;
    }
    if( len > 0) {
      regions[numregions].name = strndup(mapname, len);
    }

    //verbose("Maps: %lx-%lx, readable = %d, name: '%s'", 
    //        start, stop, (perm[0] == 'r'), mapname);

    numregions++;
  }

  fclose(f);
  return numregions;
}

void usage() {
  fprintf(stderr,
    "\n:: lindump v0.1\n"
    "Simple Linux process memory dumping utility based on ptrace\n"
    "Mariusz B., '16\n\n"
    "Usage: lindump [options] <pid> [start [stop|Llen]]\n"
    "\nArguments:\n"
    "\t<pid>\tProcess ID\n"
    "\tstart\tDumping start address, may be 0x for hex, or not for dec.\n"
    "\tstop\tUpper address to reach while dumping.\n\t\tWhen preceded with letter 'L' stands for length\n"
    "\tLlen\tSpecifies number of bytes to dump. Also may be preceded with 0x (e.g. L0x10)\n"
    "\nOptions:\n"
    "\t-o\tMemory dumps output directory (stdout hexdump otherwise, '-' for stdout)\n"
    "\t-f\tForce dumping of unreadable or inaccessible regions (still not a brute force)\n"
    "\t-v\tVerbose output.\n"
    "\t-h\tThis cruft\n"
    "\n");
}

int parse_opts(int argc, char **argv) {
  int flags, opt;

  g_params.outdir = NULL;
  g_params.force = 0;

  while ((opt = getopt(argc, argv, "hfvo:")) != -1) {
    switch(opt) {
      case 'h':
        return 0;
      case 'o':
      {
        struct stat sb;

        if (0 != strcmp(optarg, "-") && 
          !(stat(optarg, &sb) == 0 && (sb.st_mode & S_IFDIR))) {
          error("Cannot access output directory");
          return 0;
        }
        g_params.outdir = strndup(optarg, PATH_MAX);
        break;
      }
      case 'f':
        g_params.force = 1;
        break;
      case 'v':
        g_params.verbose = 1;
        break;
     default: /* '?' */
        error("Specified unknown parameter: '%c'", opt);
        return 0;
     }
  }

  if (optind >= argc) {
    error("Expected <pid> parameter at least.");
    return 0;
  }

  g_params.pid = atol(argv[optind]);
  if (g_params.pid > 65536) {
    error("Specified PID seems to be too large.");
    return 0;
  }

  if (optind + 1 < argc) {
    char *end;
    if (argv[optind+1][0] == '0' && argv[optind+1][1] == 'x') {
      g_params.start = strtoll(&argv[optind+1][2], &end, 16);
    } else {
      g_params.start = strtoll(argv[optind+1], &end, 10);
    }

    if (optind + 2 < argc) {
      uintptr_t stop;
      int isl = 0;
      if(argv[optind+2][0] == 'L') {
        isl = 1;
      }

      if (argv[optind+2][isl+0] == '0' && argv[optind+2][isl+1] == 'x') {
        g_params.stop = strtoll(&argv[optind+2][isl+2], &end, 16);
      } else {
        g_params.stop = strtoll(&argv[optind+2][isl], &end, 10);
      }

      if(isl) {
        g_params.stop += g_params.start;
      }

      if(g_params.outdir && 0 != strcmp(g_params.outdir, "-")) {
        printf("Dumping: 0x%lx-0x%lx (%d bytes)\n", 
                g_params.start, g_params.stop, (g_params.stop-g_params.start));
      }
    } else {
      verbose("Only the containing section will get dumped.");
    }
  } else {
    g_params.start = g_params.stop = 0;
  }

  return 1;
}

void cleanup(int status) {
  size_t i;

  if (g_attached) {
    verbose("Detaching from target process...");
    ptrace(PTRACE_DETACH, g_params.pid, NULL, NULL);
  }

  verbose("Freeing up allocated memory region names...");
  for(i = 0; i < g_params.numregions; i++) {
    if(g_params.regions[i].name != NULL) {
      free(g_params.regions[i].name);
    }
  }

  if(g_params.outdir != NULL) {
    free(g_params.outdir);
  }

  exit(status);
}

int main(int argc, char **argv) {
  if ( argc < 2) {
    usage();
    cleanup(-1);
  }

  memset((void*)&g_params, 0, sizeof(params));
  if (!parse_opts(argc, argv)) {
    usage();
    cleanup(-1);
  }

  verbose("Attaching to target process...");
  if(ptrace(PTRACE_ATTACH, g_params.pid, NULL, NULL)< 0 ) {
    perror("Could not attach to target process");
    cleanup(-1);
  }

  g_params.numregions = fetch_proc_memory_maps(g_params.pid, g_params.regions);
  if (g_params.numregions == 0) {
    error("Fetching process memory maps has failed.");
    cleanup(-1);
  }

  verbose("Attached. Waiting to get it.");
  wait(NULL);
  verbose("Got it.");

  int ok = 1;
  size_t i;
  uintptr_t stop;
  for(i = 0; i < g_params.numregions; i++) {
    if (g_params.regions[i].start <= g_params.start &&
          g_params.regions[i].stop >= g_params.start) {

      if(!g_params.force && !g_params.regions[i].readable) {
        error("Region: 0x%lx-0x%lx is not readable, skipping.", 
                g_params.regions[i].start, g_params.regions[i].stop);
        ok = 0;
      }
      stop = g_params.regions[i].stop;
      break;
    }
  }

  if(ok) {
    if (g_params.start != 0 && g_params.stop != 0) {
      verbose("Dumping one memory region of process %d\n", g_params.pid);
      dump(g_params.pid, g_params.start, g_params.stop, g_params.outdir);
    }
    else if(g_params.start != 0 && g_params.stop == 0) {
      verbose ("Determining memory region 0x%lx boundaries...\n", g_params.start);
      g_params.stop = stop;
      verbose("Memory region boundaries determined. Dumping one region.\n");

      if (g_params.stop == 0) {
        error("Could not determine upper memory region boundary.");
        cleanup(-1);
      }

      dump(g_params.pid, g_params.start, g_params.stop, g_params.outdir);
    }
    else {
      verbose("Dumping every readable process memory region\n");
      dump_all(g_params.pid, g_params.outdir);
    }
  }
  else {
    error("Selected memory region is stated as not readable, therefore will not be dumped.");
    cleanup(-1);
  }

  cleanup(0);
}
