#include "auth.h"
#include "hash.h"
#include <curl/curl.h>

static char *url = "https://sessionserver.mojang.com/session/minecraft/join";
static char *content_type = "application/json";
static char *useragent = "mc";
static char *auth_fmt = " \
  { \
    \"accessToken\": \"%s\", \
    \"selectedProfile\": \"%s\", \
    \"serverId\": \"%s\" \
  } \
";

static ssize_t get_serverid(serverinfo_t *si, char *buf, unsigned int *len) {
  EVP_MD_CTX *ctx = mc_hash_init(NULL);
  mc_hash_update(ctx, si->id, 20);
  mc_hash_update(ctx, si->si_encinfo.e_secret.b_data, 16);
  mc_hash_update(ctx, si->si_encinfo.e_pubkey.b_data, 162);
  mc_hash_final(ctx, buf, len);
  return len;
}

static ssize_t get_uuid(char *name) {

}

void mc_auth(serverinfo_t *si, userinfo_t *ui) {
  CURL *curl = curl_easy_init();
  if(!curl) {
    printf("%s\n", "curl error");
    return 0;
  }

  char *token = "1234";
  char *uuid = "1234";
  char *serverid = "1234";

  char post_data[256];
  sprintf(post_data, auth_fmt, token, uuid, serverid);
  printf("%s\n", post_data);
  curl_easy_setopt(curl, CURLOPT_POST, &(int) {1});
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
  curl_easy_setopt(curl, CURLOPT_USERAGENT, "mc");
  curl_easy_setopt(curl, CURLOPT_HEADER, "mc");

  if (curl_easy_perform(curl) != CURLE_OK)
    return 0;
  
  int status;
  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);

  if (status != 204)
    return 0;

  return 1;
}