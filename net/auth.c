#include "auth.h"
#include "../hash.h"
#include <curl/curl.h>

static char *auth_url = "https://sessionserver.mojang.com/session/minecraft/join";
static char *uuid_url_fmt = "https://api.mojang.com/users/profiles/minecraft/%s";
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
    mc_hash_clean(ctx);
    return len;
}

ssize_t get_uuid(char *name) {
    int maxlen = strlen(uuid_url_fmt) + 16;
    char url[maxlen + 1];
    snprintf(url, maxlen, uuid_url_fmt, name);
    CURL *curl = curl_easy_init();
    if (!curl)
        goto err;

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "Minecraft");
    printf("%s\n", url);
    if (curl_easy_perform(curl) != CURLE_OK)
        goto err;

    int status;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);

    if (status != 200)
        goto err;

    // TODO: fetch uuid via minecraft api
    //       need json parser

    curl_free(curl);
    return 1;

    err:;
    curl_free(curl);
    return 0;
}

void mc_auth(serverinfo_t *si, userinfo_t *ui) {
    CURL *curl = curl_easy_init();
    if (!curl)
        goto err;

    char *token = "1234";
    char *uuid = "83e466a10d6b489db7200e2a73588fc8";
    char serverid[SHA_DIGEST_LENGTH + 1];
    get_serverid(si, serverid, SHA_DIGEST_LENGTH + 1);

    char post_data[256];
    sprintf(post_data, auth_fmt, token, uuid, serverid);
    printf("%s\n", post_data);
    curl_easy_setopt(curl, CURLOPT_URL, auth_url);
    curl_easy_setopt(curl, CURLOPT_POST, &(int){1});
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "Minecraft");

    if (curl_easy_perform(curl) != CURLE_OK)
        goto err;

    int status;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);

    if (status != 204)
        goto err;

    curl_free(curl);
    return 1;

    err:;
    curl_free(curl);
    return 0;
}