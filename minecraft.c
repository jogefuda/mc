#include "minecraft.h"
#include "utils.h"
#include "net/pkt.h"
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>

static void _mc_eventloop(struct serverinfo *si) {
    // TODO: this currently not working.
    int ret;
    int epoll_fd = epoll_create(4);
    int sock_fd = si->si_conninfo.sockfd;
    if (epoll_fd == -1) {
        // TODO: err handle
    }

    struct epoll_event event = {
        .data = sock_fd,
        .events = EPOLLIN | EPOLLERR | EPOLLET
    };

    ret = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sock_fd, &event);

    struct epoll_event events[4];
    for (;;) {
        int n_event = epoll_wait(epoll_fd, events, 1, -1);
        uint32_t e = events[0].events;

        if (e == EPOLLIN) {
            read_packet(si, NULL, NULL);
        } else if (e == EPOLLERR) {
            break;
        }
    }
    close(epoll_fd);
}

struct serverinfo *mc_connect(const char *host, uint16_t port, uint32_t proto) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);

    if (fd < 0) {
        fprintf(stderr, "Fail to create socket: %s", strerror(errno));
        return NULL;
    }

    struct sockaddr_in sin = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
    };

    int ret;
    ret = inet_pton(AF_INET, host, &sin.sin_addr);
    if (ret != 1) {
        fprintf(stderr, "Not a vail address: %s", strerror(errno));
        return NULL;
    }

    ret = connect(fd, (struct sockaddr *)&sin, sizeof(struct sockaddr_in));
    if (ret != 0) {
        fprintf(stderr, "Fail to connect to host: %s", strerror(errno));
        return NULL;
    }

    struct serverinfo *si = malloc(sizeof(struct serverinfo));

    if (si == NULL) {
        fprintf(stderr, "Fail to malloc: %s", strerror(errno));
        return NULL;
    }

    // memset(si, 0, sizeof(struct serverinfo));
    si->si_encinfo = malloc(sizeof(struct encrypt));
    if (!si->si_encinfo) {
        // TODO: error handle
        return 0;
    }
    memset(si->si_encinfo, 0, sizeof(struct encrypt));

    si->si_conninfo.sockfd = fd;
    si->si_conninfo.addr = host;
    si->si_conninfo.port = port;
    si->si_conninfo.proto = proto;
    return si;
}

void mc_eventloop(struct serverinfo *si) {
    pthread_t t;
    pthread_create(&t, NULL, _mc_eventloop, si);
}

void mc_getinfo(struct serverinfo *si, enum MC_REQ info) {
    si->si_conninfo.state = MC_STATUS_HANDSHAKE;
    send_packet(MC_REQ_HANDSHAKE, si, NULL, NULL);

    switch (info) {
        case MC_REQ_PING:;
            // TODO: change this to unix time
            uint64_t time = 0x12345678;
            send_packet(MC_REQ_PING, si, NULL, &time);
            break;
        case MC_REQ_SPL:;
            send_packet(MC_REQ_SPL, si, NULL, NULL);
            break;
    };
}

void mc_login(struct serverinfo *si, struct userinfo *ui) {
    si->si_conninfo.state = MC_STATUS_LOGIN;
    send_packet(MC_REQ_HANDSHAKE, si, NULL, NULL);
    send_packet(MC_REQ_LOGIN, si, ui, NULL);
}

void mc_wait_until_login_success(struct serverinfo *si) {
    // TODO: use mutex instade of sleep
    while (si->si_conninfo.state != MC_STATUS_PLAY) {
        puts("==== waiting ====\n");
        sleep(1);
    }
}

void mc_chat(struct serverinfo *si, const char *msg) {
    send_packet(MC_REQ_CHAT, si, NULL, msg);
}

void mc_set_difficult(struct serverinfo *si, int32_t level) {
    send_packet(MC_REQ_SET_DIFFICULT, si, NULL, &(int32_t){level});
}

void mc_init_cipher(struct serverinfo *si) {
    char *iv = si->si_encinfo->e_secret->b_data;
    si->si_encinfo->e_encctx = aes_cipher_init(iv, iv, 1);
    si->si_encinfo->e_decctx = aes_cipher_init(iv, iv, 0);
}

void mc_cleanup(struct serverinfo *si) {
    // NOTE: serverinfo->e_encinfo is not free yet!

    if (!si) return;

    shutdown(si->si_conninfo.sockfd, SHUT_WR);
    close(si->si_conninfo.sockfd);

    if (si->si_encinfo) {
        if (si->si_encinfo->e_encctx)
            aes_cipher_free(si->si_encinfo->e_encctx);
        if (si->si_encinfo->e_decctx)
            aes_cipher_free(si->si_encinfo->e_decctx);
        if (si->si_encinfo->e_id)
            del_buffer(si->si_encinfo->e_id);
        if (si->si_encinfo->e_pubkey)
            del_buffer(si->si_encinfo->e_pubkey);
        if (si->si_encinfo->e_verify)
            del_buffer(si->si_encinfo->e_verify);
        if (si->si_encinfo->e_secret)
            del_buffer(si->si_encinfo->e_secret);
    }

    free(si);
}
