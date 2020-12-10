#include "minecraft.h"
#include "compress.h"
#include "net/auth.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "hash.h"
#include <openssl/evp.h>

void mc_init_decrypter(struct serverinfo *si);
int main(int argc, char *argv[]) {
    openssl_load_err_str();
    struct serverinfo *si = mc_connect("127.0.0.1", 25565, MC_1_6_4);
    struct userinfo ui = {
        .ui_name = "didiche"
    };

    // mc_getinfo(si, MC_REQ_SPL);
    mc_login(si, &ui);
    mc_eventloop(si);
    mc_wait_until_login_success(si);
    mc_chat(si, "Cursed world");
    char buf[256];
    for (size_t i = 0; i < 30; i++) {
        sprintf(buf, "%s, %d!", "Hello", i);
        sleep(1);
        mc_chat(si, buf);
    }

    // dump(b->b_data, b->b_size);
    // mc_wait_until_login_success(si);
    mc_cleanup(si);

    return 0;
}
