#include "pkt.h"
#include "../crypto.h"
#include "../utils.h"

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

// debug
#include <fcntl.h>

// deserializer
static ssize_t deserialize_varint(int fd, int32_t *out) {
  uint8_t tmp;
  size_t nbytes = 0;
  ssize_t n;
  *out = 0;

  do {
    if ((n = read(fd, &tmp, 1)) < 1)
      return n;
    *out |= tmp << (7 * nbytes++);
  } while (tmp & 0b10000000);

  return nbytes;
}

static ssize_t deserialize_str(int fd, char **buf, size_t *n) {
  int32_t len;
  ssize_t _n;
  char *pstr;

  if ((_n = deserialize_varint(fd, &len)) < 1)
    return _n;

  if (len == 0)
    return 0;

  if (len > *n) {
    if ((pstr = realloc(*buf, len)) == NULL) {
      return -1;
    }
    *buf = pstr;
    *n = len;
  }

  if ((_n = read(fd, *buf, len)) < 1)
    return _n;

  return len;
}

// serializer
static ssize_t serialize_varint(char *buf, int32_t val)
{
  char *_buf = buf;
  uint32_t _val = val;
  char tmp;
  ssize_t n = 0;

  do
  {
    tmp = _val & 0b01111111;
    _val >>= 7;
    if (_val != 0)
      tmp |= 0b10000000;

    *_buf++ = tmp;
    ++n;
  } while (_val != 0);

  return n;
}

static ssize_t serialize_short(char *buf, short val)
{
  buf[0] = (val >> 8) & 0xff;
  buf[1] = val & 0xff;
  return sizeof(short);
}

static ssize_t serialize_str(char *buf, const char *str, const ssize_t n)
{
  ssize_t vl = serialize_varint(buf, n);
  buf += vl;
  ssize_t _n = n;

  for (; _n; _n--)
    *buf++ = *str++;

  return vl + n;
}

// read packet
static ssize_t recv_encrypt_req(struct serverinfo *si) {
  int fd  = si->si_conninfo.sockfd;
  char buf[256];

  // TODO: serverinfo.id is not not relocateable
  // ERROR HANDLE
  size_t len = 20;
  len = deserialize_str(fd, &si->id, &len);
  deserialize_str(fd, &si->si_encinfo.e_pubkey.b_data, &si->si_encinfo.e_pubkey.b_size);
  deserialize_str(fd, &si->si_encinfo.e_verify.b_data, &si->si_encinfo.e_verify.b_size);
  return 0;
}

//
ssize_t read_response(struct serverinfo *si, struct userinfo *ui, void *userdata) {
  int fd = si->si_conninfo.sockfd;
  int32_t len, type, state;

  state = si->si_conninfo.state;
  size_t nbytes = 0;
  nbytes += deserialize_varint(fd, &len);
  nbytes += deserialize_varint(fd, &type);

  printf("pkgsize: %d, %zd\n", len, nbytes);
  char *buf = malloc(len);

  if (state == MS_LOGIN) {
    switch(type) {
        case MP_ENCRYPT_REQ:
          recv_encrypt_req(si);
        break;
  int nr;
  // nr = read(fd, buf, len);
    };
  }
  return 0;
}


// send packet
ssize_t send_handshake(struct serverinfo *si, int state)
{
  char *buf = malloc(64);
  char *pbuf = buf + 5; //reserve for size field.

  ssize_t pkgsize = 0;
  pkgsize += serialize_varint(pbuf, MP_HANDSHAKING);
  pkgsize += serialize_varint(pbuf + pkgsize, si->si_conninfo.proto);
  pkgsize += serialize_str(pbuf + pkgsize, si->si_conninfo.addr, strlen(si->si_conninfo.addr));
  pkgsize += serialize_short(pbuf + pkgsize, si->si_conninfo.port);
  pkgsize += serialize_varint(pbuf + pkgsize, state);

  pbuf = buf;
  ssize_t len;
  len = serialize_varint(pbuf, pkgsize);
  len = write(si->si_conninfo.sockfd, buf, len);
  len += write(si->si_conninfo.sockfd, buf + 5, pkgsize);
  si->si_conninfo.state = state;
  free(buf);
  return len;
}

ssize_t send_slp(struct serverinfo *si)
{
  char buf[2] = {0x01, MP_SLP}; // length, type
  return write(si->si_conninfo.sockfd, buf, sizeof(buf));
}

ssize_t send_ping(struct serverinfo *si, long data)
{
  char buf[10] = {0x09, MP_PING}; // length, type
  // TODO: if data is 0, use current time instade.
  *(long *)(buf + 2) = data;
  return write(si->si_conninfo.sockfd, buf, sizeof(buf));
}

ssize_t send_login(struct serverinfo *si, struct userinfo *ui) {
  int fd = si->si_conninfo.sockfd;
  char *buf = (char *)malloc(32);
  char *pbuf = buf + 5;

  size_t pkgsize = 0;
  pkgsize += serialize_varint(pbuf + pkgsize, MP_LOGIN);
  pkgsize += serialize_str(pbuf + pkgsize, ui->ui_name, strlen(ui->ui_name));

  ssize_t len = serialize_varint(buf, pkgsize);
  write(fd, buf, len);
  write(fd, buf + 5, pkgsize);
  return pkgsize;
}

ssize_t send_encryption(struct serverinfo *si) {
  int fd = si->si_conninfo.sockfd;

  struct bytearray *secret = &si->si_encinfo.e_secret;
  secret->b_data = malloc(16);

  int len = gen_rand_byte(secret, 16);

  if(len < 16) {
    perror("Fail to generate secret. Reason:");
    return -1;
  }

  struct bytearray verifytk = si->si_encinfo.e_verify;
  struct bytearray crypted_secret;
  struct bytearray crypted_verifytk;

  int nbytes = 0;
  RSA *rsa = DER_load_pubkey_from_str(&si->si_encinfo.e_pubkey);
  nbytes += RSA_encrypt_with_pubkey(rsa, secret, &crypted_secret);
  nbytes += RSA_encrypt_with_pubkey(rsa, &verifytk, &crypted_verifytk);
  
  char *buf = malloc(512);
  char *pbuf = buf + 5;
  size_t pktsize = 0;
  pktsize += serialize_varint(pbuf + pktsize, MC_ENCRYPT);
  pktsize += serialize_str(pbuf + pktsize, crypted_secret.b_data, crypted_secret.b_size);
  pktsize += serialize_str(pbuf + pktsize, crypted_verifytk.b_data, crypted_verifytk.b_size);
  len = serialize_varint(buf, pktsize);

  write(fd, buf, len);
  write(fd, buf + 5, pktsize);
  return 0;
}


ssize_t send_chat(struct serverinfo *si, const char *str) {
  char buf[280], *pbuf;
  int fd = si->si_conninfo.sockfd;
  pbuf = buf + 5;
  size_t pktsize = 0;
  pktsize += serialize_varint(pbuf + pktsize, MP_CHAT);
  pktsize += serialize_str(pbuf + pktsize, str, strlen(str));
 
  int len = serialize_varint(buf, pktsize);
  write(fd, buf, len);
  write(fd, buf + 5, pktsize);
}