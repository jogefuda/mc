#ifndef __MINECRAFT_H
#define __MINECRAFT_H

#include "net/pkt.h"
#include "version.h"
#include <sys/types.h>

typedef int MCINFO;
#define MCINFO_SERVER_INFO 0x00
#define MCINFO_PING 0x01

struct serverinfo *mc_connect(const char *host, uint16_t port, uint32_t proto);
void mc_login(struct serverinfo *si, struct userinfo *ui);
void mc_getinfo(struct serverinfo *si, MCINFO type);
void mc_eventloop(struct serverinfo *si);
void mc_cleanup(void *ptr);



#endif // __MINECRAFT_H