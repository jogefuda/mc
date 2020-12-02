#include "pkt.h"

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

// utils
#define vitoh(__v, __n) ((int)vitohl(__v, __n))
#define vitohs(__v, __n) ((short)vitohl(__v, __n))
long vitohl(const byte *const buf, size_t *len)
{
  long ret = 0;
  size_t nRead = 0;
  byte *_buf = (byte *)buf;

  do
  {
    ret += (*_buf & 0b01111111) << (7 * nRead++);
  } while ((*_buf++ & 0b10000000) > 0);

  if (len != NULL)
    *len = nRead;

  return ret;
}


// deserializer
static ssize_t deserialize_varint(int fd, int32_t *out) {
  uint8_t tmp;
  size_t nbytes = 0;
  ssize_t n;
  *out = 0;

  do {
    if ((n = read(fd, &tmp, 1)) <= 0)
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
// TODO: change val type to signed int.
static ssize_t serialize_varint(char *buf, uint32_t val)
{
  char *_buf = buf;
  char tmp;
  ssize_t n = 0;

  do
  {
    tmp = val & 0b01111111;
    val >>= 7;
    if (val != 0)
      tmp |= 0b10000000;

    *_buf++ = tmp;
    ++n;
  } while (val != 0);

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

  for (_n; _n; _n--)
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
  len = deserialize_str(fd, si->id, &len);
  deserialize_str(fd, &si->si_encinfo.e_pubkey.b_arr, &si->si_encinfo.e_pubkey.b_len);
  deserialize_str(fd, &si->si_encinfo.e_verify.b_arr, &si->si_encinfo.e_verify.b_len);
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

  printf("pkgsize: %d, %d\n", len, nbytes);
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
  // si->si_encinfo.e_presharekey();
}