#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "utils.h"
#include "minecraft.h"

int main(int argc, char *argv[]) {
  openssl_load_err_str();
  
  struct serverinfo *si = mc_connect("127.0.0.1", 25565, MC_1_6_4);

  int len;
  char buf[256];
 
  read(si->si_conninfo.sockfd, buf, 128);
  dump(buf, 128);
  return 0;
}
