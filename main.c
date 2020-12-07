#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "utils.h"
#include "minecraft.h"
#include "compress.h"

int main(int argc, char *argv[]) {
  openssl_load_err_str();
  // struct serverinfo *si = mc_connect("127.0.0.1", 25565, MC_1_6_4);
  // mc_eventloop(si);
  // mc_getinfo(si, MCINFO_PING);
  bytearray_t *in = bytearray_create(128);
  bytearray_t *out = bytearray_create(128);

  in->b_size = sprintf(in->b_data, "%s\n", "12345678");
  mc_deflat_pkt(in, out);

  printf("%s\n", out->b_data);
  printf("out size: %d", out->b_allocsize);
  
  // mc_cleanup(si);
  return 0;
}
