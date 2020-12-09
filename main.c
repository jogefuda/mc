#include "minecraft.h"
#include "compress.h"
#include "net/auth.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "hash.h"

int main(int argc, char *argv[]) {
    openssl_load_err_str();
    struct serverinfo *si = mc_connect("127.0.0.1", 25565, MC_1_6_4);
    struct userinfo ui = {
        .ui_name = "Hello"
    };

    // mc_eventloop(si);
    // mc_getinfo(si, MC_REQ_SPL);
    // mc_login(si, &ui);
    // sleep(1); // TODO: wait until connection change to play state
    // read_packet(si, 0, 0);
    // mc_chat(si, "Cursed world");

    char out[42] = { 0 };
    void *ctx = mc_hash_init(NULL);
    mc_hash_update(ctx, "jeb_", 4);
    mc_hash_final(ctx, out, 40);
    printf("%s\n", out);

    getchar();
    mc_cleanup(si);
    return 0;
}
