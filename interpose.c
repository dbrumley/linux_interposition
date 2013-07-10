#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <execinfo.h>
#include <string.h>
#include <stdarg.h>
#include <mcheck.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dlfcn.h>

/* 
extern char *program_invocation_name; 
extern char *program_invocation_short_name;
*/

/* 
   NOTE!!!  We must be very careful about functions we call as part of
   our code, and the hooking code. If we hook function x, and then
   call x somewhere else from a utility function we wrote (e.g.,
   because we're not thinking and need x in our logging), then we
   could end up with a recursive loop between our utility function.
*/

/* mtrace() is called to initialize memory tracing to find bugs.
   However, we should only call it once. Note that mtrace()
   recursively calls malloc, so we also don't want to cause an
   infinite loop where malloc->mtrace->malloc->mtrace.  */
static int mtrace_init = 0;

/* The environment name of file we log to. If not set, no logging. */
const char *log_envname = "FAS_INTERPOSE_LOG";

/* The environment variable name that has the fuzz string */
const char *fuzz_envname = "FAS_FUZZ_STRING";

/* The maximum number of stack frames to walk */
#define MAX_WALK_FRAMES 25

/* Our logging function. For now, we open and close the file on each
   log message so that the fact there is a new file descriptor is
   transparent to the client program. In the future, we may change if
   efficiency opening and closing on each call becomes an issue */
void logit(const char *fmt, ...)
{
  va_list args;
  char *filename;
  static FILE *f = NULL;

  filename = getenv(log_envname);
  if(filename == NULL){
    return;
  }

  if(f == NULL){
    f =fopen(filename, "a+");
    if(f == NULL)
      return;
  }
  va_start(args, fmt);  
  vfprintf(f, fmt, args);
  va_end(args);
}

/* Our check for the fuzzing string */
int has_fuzzstring(const char *src)
{
  static char *fuzzstring = NULL;
  static int check_fuzz = 1;
  
  if(check_fuzz == 0) return 0;

  if(fuzzstring == NULL){
    fuzzstring = getenv(fuzz_envname);
    if(fuzzstring == NULL){
      check_fuzz = 0;
      return 0;
    }
  }

  if((src != NULL) && (strstr(src, fuzzstring) != NULL))
    return 1;
  return 0;
}


struct stack_frame {
  struct stack_frame* next;  /* frame pointer */
  void* ret;                 /* return address */
};

/* 
   This is a simple variation of the glibc backtrace() function.  We
   don't use backtrace() because we want the frame pointers on the
   stack, and backtrace() just returns the return addresses on the
   stack. Note Matt has a nicer stackwalker that works for x86_64,
   which we now use. Included here for reference, but should be dead
   code.  
 */
int get_call_stack(void** retaddrs, int max_size) {
  /* x86/gcc-specific: this tells gcc that the fp
     variable should be an alias to the %ebp register
     which keeps the frame pointer */
  register struct stack_frame* fp asm("ebp");
  /* the rest just walks through the linked list */
  struct stack_frame* frame = fp;
  int i = 0;
  while(frame && (i < max_size)) {
    if(i < max_size) {
      retaddrs[i++] = frame->next;
    }
    frame = frame->next;
  }
  return i;
}

void seek_addr(int fd, void* addr) {
  if ((off_t)addr < 0) {
    off_t mod = ((unsigned int)addr) >> 1;
    lseek(fd, mod, SEEK_SET);
    addr -= mod;
    lseek(fd, (off_t)addr, SEEK_CUR);
  } else {
    lseek(fd, (off_t)addr, SEEK_SET);
  }
}
 
void* deref(int fd, void* addr) {
  void* res;
  seek_addr(fd, addr);
  if (read(fd, &res, sizeof(res)) != sizeof(res))
    return NULL;
  return res;
}
 
size_t stackwalk(void** frames, size_t frame_len) {
  struct stack_frame* fb = __builtin_frame_address(0);
  size_t i;
  int fd = open("/proc/self/mem", O_RDONLY);
  for (i = 0; ((frame_len > i) && (fb != NULL)); fb = deref(fd, &fb->next), i++)
    frames[i] = fb;
  close(fd);
  return i;
}

unsigned int est_buf_len(unsigned int dest)
{
  int nptrs;
  unsigned int len = 0;
  int j = 0;
  void *buffer[MAX_WALK_FRAMES];
  if(dest > 0xbfffffff) return 0;
  if(dest < 0xbf700000) return 0;
  nptrs = stackwalk(buffer, MAX_WALK_FRAMES);
  if(nptrs == 0) return 0;
  while((j < nptrs) && ( ((unsigned int) buffer[j]) <  dest)) j++;
  len  =  ((unsigned int) buffer[j]) - dest;

  return len;
}


char *strcpy(char *dest, const char *src)
{
  static void* (*real_strcpy)(char *, const char*) = NULL;
  
  unsigned long buffer[100];
  int len, nptrs;

  if(!real_strcpy)
    real_strcpy = dlsym(RTLD_NEXT, "strcpy");
  if(has_fuzzstring(src)){
    len = est_buf_len((unsigned int) dest);
    logit("USER_CONTROLLABE_STRCPY: strcpy(%p,%p) : |%p| = %d\n", 
	  dest, src, dest, len);
  }
  return real_strcpy(dest, src);
}

char *strcat(char *dest, const char *src)
{
  static void* (*real_strcat)(char *, const char*) = NULL;
  unsigned int len;

  if(!real_strcat)
    real_strcat = dlsym(RTLD_NEXT, "strcat");
  if(has_fuzzstring(src)){
    len = est_buf_len((unsigned int) dest);
    logit("USER_CONTROLLABE_STRCAT: strcat(%p,%p) : |%p| = %d\n", 
	  dest, src, dest, len);
  }
  return real_strcat(dest, src);
}

char *gets(char *s)
{
  static void* (*real_gets)(char *) = NULL;
  int len = 0;

  if(!real_gets)
    real_gets = dlsym(RTLD_NEXT, "gets");
  if(has_fuzzstring(s)){
    len = est_buf_len((unsigned int) s);
    logit("USER_CONTROLLABE_GETS: gets(%p) : |%p| = %d\n", 
	  s, s, len);
  }
  return real_gets(s);
}


int system(const char *command)
{
  static void* (*real_system)(const char*) = NULL;
 
  if(!real_system)
    real_system = dlsym(RTLD_NEXT, "system");
  
  if(has_fuzzstring(command)){
    logit("USER_CONTROLLABE_SYSTEM: system(%p)\n", command);
  }
  else if(command && command[0] != '/'){
    logit("SYSTEM_WITHOUT_FQP: system(%p)\n", command);

  }

  return (int) real_system(command);
}

int printf(const char *fmt, ...)
{
  va_list args;
  int result;
  va_start(args, fmt);
  if(has_fuzzstring(fmt)){
    logit("USER_CONTROLLABE_PRINTF_FORMAT: printf(%p,...)\n", fmt);
  }
  result = vprintf(fmt, args);
  va_end(args);
  return result;
}

int fprintf(FILE *fd, const char *fmt, ...)
{
  va_list args;
  int result;
  va_start(args, fmt);
  if(has_fuzzstring(fmt)){
    logit("USER_CONTROLLABE_FPRINTF_FORMAT: fprintf(fd,%p,...)\n", fmt);
  }
  result = vfprintf(fd,fmt, args);
  va_end(args);
  return result;
}

/* xxx: we should also get the length of str if any argument is user
   controllable. I'm not sure how to do this. Solutions anyone? --djb
*/
int sprintf(char *str, const char *fmt, ...)
{
  va_list args;
  int result;
  int len;

  va_start(args, fmt);
  if(has_fuzzstring(fmt)){
    len = est_buf_len((unsigned int) str);
    logit("USER_CONTROLLABE_SPRINTF_FORMAT: sprintf(str,%p,...) : |str| = %d\n",
  	  fmt, len);
  }
  result = vsprintf(str,fmt, args);
  va_end(args);
  return result;
}

void my_init_hook()
{
  mtrace();
}

/* see man page for malloc_hook(). __malloc_initialize_hook is called
   when malloc is initialized. Here we are saying to start mtrace. */  
void (*__malloc_initialize_hook)(void) = my_init_hook;


