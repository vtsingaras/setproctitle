#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/ptrace.h>

#define PRINT_USAGE() printf("Usage: %s -pid PID -title TITLE\n", argv[0]);

void hexdump(void *ptr, int buflen) {
  unsigned char *buf = (unsigned char*)ptr;
  int i, j;
  for (i=0; i<buflen; i+=16) {
    printf("%06x: ", i);
    for (j=0; j<16; j++) 
      if (i+j < buflen)
        printf("%02x ", buf[i+j]);
      else
        printf("   ");
    printf(" ");
    for (j=0; j<16; j++) 
      if (i+j < buflen)
        printf("%c", isprint(buf[i+j]) ? buf[i+j] : '.');
    printf("\n");
  }
}

int setproctitle(unsigned int pid, char* title) {
  char buf[2048], *tmp;
  FILE *f;
  int i, ret = 0;
  size_t len, peek_poke_num_words = 0;
  unsigned long arg_start, arg_end, peek_poke_start, peek_poke_end, *peek_poke_buf;

  sprintf(buf, "/proc/%d/stat", pid);
  errno = 0;
  f = fopen(buf, "r");
  if (!f) {
    printf("Invalid PID specified.\n");
    return -1;
  }

  tmp = fgets(buf, sizeof(buf), f);
  fclose(f);
  if (!tmp) {
    printf("Error reading /proc/PID/stat. Use strace for more info.");
    return -1;
  }

  tmp = strchr(buf, ' ');
  for (i = 0; i < 46; i++) {
    if (!tmp) {
      printf("/proc/PID/format changed?\n");
      return -1;
    }
    tmp = strchr(tmp+1, ' ');
  }

  if (!tmp)
    return -1;

  i = sscanf(tmp, "%lu %lu", &arg_start, &arg_end);
  if (i != 2) {
    printf("/proc/PID/format changed?\n");
    return -1;
  }

  len = strlen(title) + 1;

  if (len > arg_end - arg_start) {
    printf("Can't set a title that is larger than the current one :(");
    return -1;
  } else if (len < arg_end - arg_start) {
    for (i = len; i < arg_end - arg_start; i++) {
      strcat(title, " ");
    }
  }

  if (ret = ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
    printf("Unable to attach... Maybe you are using GDB or ptrace is blocked in your system.\n");
    return -1;
  }
  /* Clear low bits to make addresses word-aligned for ptrace;
     for peek_poke_end also increment by one word */
  peek_poke_start = arg_start & ~(sizeof(long) - 1);
  peek_poke_end = (arg_end & ~(sizeof(long) - 1)) + sizeof(long);
  peek_poke_num_words = (peek_poke_end - peek_poke_start) / sizeof(long);
  peek_poke_buf = malloc(peek_poke_num_words * sizeof(long));

  for (i = 0; i < peek_poke_num_words; i++){
    if ( (ret = ptrace(PTRACE_PEEKDATA, pid, peek_poke_start + i*sizeof(long), NULL)) == -1) {
      printf("Error setting the new title.\n");
      return -1;
    }
    peek_poke_buf[i] = ret;
  }

  strcpy((char*)peek_poke_buf + arg_start - peek_poke_start, title);

  for (i = 0; i < peek_poke_num_words; i++){
    if (ptrace(PTRACE_POKEDATA, pid, peek_poke_start + i*sizeof(long), peek_poke_buf[i]) == -1) {
      printf("Error setting the new title. Target potentially left in incosistent state.\n");
      return -1;
    }
  }
  if (ptrace(PTRACE_CONT, pid, 0, 0) == -1) {
    printf("Error setting the new title while resuming the process. Target potentially left in incosistent state.\n");
    return -1;
  }

  return 0;
}

int main(int argc, char **argv) {
  unsigned int pid = 0;
  char *title = NULL, opt = '\0';

  if (geteuid() != 0) {
    printf("Error: This utility requires root privileges.\n");
    return EXIT_FAILURE;
  }

  static struct option long_options[] = {
    {"pid", required_argument, NULL, 'p'},
    {"title", required_argument, NULL, 't'},
    {NULL, 0, NULL, NULL}
  };

  while ((opt = getopt_long(argc, argv, "p:t:", long_options, NULL)) != -1) {
    switch (opt) {
      case 'p':
        errno = 0;
        pid = strtoul(optarg, NULL, 10);
        if (errno != 0) {
          pid = 0;
        }
        break;
      case 't':
        title = strdup(optarg);
        break;
      default:
        PRINT_USAGE();
        return EXIT_FAILURE;
    }
  }

  if (pid == 0 || title == NULL) {
    PRINT_USAGE();
    return EXIT_FAILURE;
  }

  if (0 == setproctitle(pid, title)) {
    return EXIT_SUCCESS;
  }

  return EXIT_FAILURE;
}
