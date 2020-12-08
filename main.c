#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "utils.h"
#include "minecraft.h"
#include "compress.h"

int main(int argc, char *argv[])
{
    openssl_load_err_str();
    struct serverinfo *si = mc_connect("127.0.0.1", 25565, MC_1_6_4);
    mc_eventloop(si);
    mc_getinfo(si, 2);
    bytearray_t *in = new_bytearray(128);
    bytearray_t *out = new_bytearray(2);

    read_packet(si, NULL, NULL);

    mc_cleanup(si);
    return 0;
}
