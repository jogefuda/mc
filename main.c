#include "minecraft.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    struct serverinfo *si = mc_connect("127.0.0.1", 25565, MC_1_6_4);
    struct userinfo ui = {
        .ui_name = "-東風一號."
    };

    mc_eventloop(si);
    mc_login(si, &ui);
    mc_wait_until_login_success(si);
    char buf[256] = "";
    for (size_t i = 0; i < 10; i++) {
        sprintf(buf, "Hello Wold! %d\n", i);
        mc_chat(si, buf);
        sleep(1);
    }

    getchar(); // TODO: wait until send/recv disconnect packet
    mc_cleanup(si);
    return 0;
}
