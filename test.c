//#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>



void copy_it(char *src)
{
  char buf[0xee];
  strcpy(buf, src);
  printf("%s\n", src);
}

extern char **environ;

int main(int argc, char *argv[])
{
  char *ptr;
  char buf[0xff];
  int i = 0;
  copy_it(argv[1]);
  copy_it("constant");
  printf(argv[1]);
  sprintf(buf, argv[1]);
  ptr = malloc(0xf);
}
