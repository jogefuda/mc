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
        .ui_name = "nenezuko"
    };

    // mc_getinfo(si, MC_REQ_SPL);
    mc_login(si, &ui);
    mc_eventloop(si);
    // TODO: use event loop
    // read_packet(si, 0, 0); // encrypt pkt
    // read_packet(si, 0, 0); // setcomp pkt
    // read_packet(si, 0, 0); // loginsucc pkt
    // read_packet(si, 0, 0); // first game pkt

    mc_wait_until_login_success(si);
    mc_chat(si, "Hello world");
    mc_chat(si, "Cursed world");
    // mc_wait_until_login_success(si);
    getchar();
    mc_cleanup(si);

    return 0;
}
