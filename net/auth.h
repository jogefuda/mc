#ifndef __AUTH_H
#define __AUTH_H

#include "pkt.h"
#include <sys/types.h>

ssize_t get_uuid(char *name);
int mc_auth(serverinfo_t *si, userinfo_t *ui);
#endif // __AUTH_H
