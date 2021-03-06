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
        .data.fd = sock_fd,
        .events = EPOLLIN | EPOLLHUP | EPOLLERR
    };

    ret = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sock_fd, &event);

    struct epoll_event events[4];
    for (;;) {
        int n_event = epoll_wait(epoll_fd, events, 1, -1);
        uint32_t e = events[0].events;

        if (e == EPOLLIN) {
            ret = read_packet(si, NULL, NULL);
        } else if (e == EPOLLERR || e == EPOLLHUP) {
            break;
        }

        if (ret == -1) break;
    }
    close(epoll_fd);
}

char *mc_err_getstr(enum M_ERR err) {
    switch (err) {
        case M_ERR_MEMORY: return "Fail to memory allocation"; break;
        case M_ERR_INFLAT: return "Fail to decompress packet"; break;
        case M_ERR_DEFLAT: return "Fail to compress packet"; break;
        case M_ERR_ENCRYPT: return "Fail to encrypt packet"; break;
        case M_ERR_DECRYPT: return "Fail to decrypt packet"; break;
        case M_ERR_PUBKEY: return "Fail to parse public key. reason: %s"; break;
        case M_ERR_SECRETKEY: return "Fail to generate secret key"; break;
        case M_ERR_CIPHER: return "Fail to init cipher. reason %s"; break;
        case M_ERR_DIGEST: return "Fail to generate digest"; break;
        case M_ERR_DATA: return "Fail to read data"; break;
        default: return "No mapping"; break;
    }
}

struct serverinfo *mc_connect(const char *host, uint16_t port, uint32_t proto) {
    openssl_load_err_str();
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
        fprintf(stderr, "Not a vail address: %s\n", strerror(errno));
        return NULL;
    }

    ret = connect(fd, (struct sockaddr *)&sin, sizeof(struct sockaddr_in));
    if (ret != 0) {
        fprintf(stderr, "Fail to connect to host: %s\n", strerror(errno));
        return NULL;
    }

    struct serverinfo *si = malloc(sizeof(struct serverinfo));

    if (si == NULL) {
        fprintf(stderr, "Fail to alloc memory: %s\n", strerror(errno));
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
    // TODO: wait until epoll is in ready state
    pthread_t t;
    pthread_create(&t, NULL, (void *)_mc_eventloop, si);
}

void mc_getinfo(struct serverinfo *si, enum M_REQ info) {
    si->si_conninfo.state = M_STATE_HANDSHAKE;
    send_packet(M_REQ_HANDSHAKE, si, NULL, NULL);

    switch (info) {
        case M_REQ_PING:;
            // TODO: change this to unix time
            uint64_t time = 0x12345678;
            send_packet(M_REQ_PING, si, NULL, &time);
            break;
        case M_REQ_SPL:;
            send_packet(M_REQ_SPL, si, NULL, NULL);
            break;
    };
}

void mc_login(struct serverinfo *si, struct userinfo *ui) {
    si->si_conninfo.state = M_STATE_LOGIN;
    send_packet(M_REQ_HANDSHAKE, si, NULL, NULL);
    send_packet(M_REQ_LOGIN, si, ui, NULL);
}

void mc_wait_until_login_success(struct serverinfo *si) {
    // TODO: use mutex instade of sleep
    while (si->si_conninfo.state != M_STATE_PLAY) {
        puts("==== waiting ====\n");
        sleep(1);
    }
}

void mc_chat(struct serverinfo *si, const char *msg) {
    send_packet(M_REQ_CHAT, si, NULL, (void *)msg);
}

void mc_set_difficult(struct serverinfo *si, int32_t level) {
    send_packet(M_REQ_SET_DIFFICULT, si, NULL, &(int32_t){level});
}

int mc_init_cipher(struct serverinfo *si) {
    /* Init cipher for encrypt and decrypt */
    char *iv = si->si_encinfo->e_secret->b_data;
    si->si_encinfo->e_encctx = aes_cipher_init(iv, iv, 1);
    si->si_encinfo->e_decctx = aes_cipher_init(iv, iv, 0);

    // TODO: Do i need clean the ctx ?
    if (si->si_encinfo->e_encctx == NULL || si->si_encinfo->e_decctx == NULL)
        return M_FAIL;

    return M_SUCCESS;
}

void mc_cleanup(struct serverinfo *si) {
    if (!si) return;

    shutdown(si->si_conninfo.sockfd, SHUT_RDWR);
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


void mc_player_move(struct serverinfo *si, double x, double y, double z, int ground) {
}

void mc_player_lookat(struct serverinfo *si, double pitch, double law) {
}