/* Build-time PGO driver. Creates a separate synthetic database, never the live
 * file. */
#include "app.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static Response result;
static void sql(sqlite3 *d, const char *s) {
  if (sqlite3_exec(d, s, NULL, NULL, NULL) != SQLITE_OK) {
    fprintf(stderr, "training SQL: %s\n", sqlite3_errmsg(d));
    exit(1);
  }
}
static void seed(const char *path) {
  unlink(path);
  sqlite3 *d;
  sqlite3_open(path, &d);
  sql(d,
      "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; BEGIN;"
      "CREATE TABLE users(id INTEGER PRIMARY KEY,username TEXT NOT NULL "
      "UNIQUE,created_at TEXT NOT NULL "
      "DEFAULT(strftime('%Y-%m-%dT%H:%M:%fZ','now')));"
      "CREATE TABLE posts(id INTEGER PRIMARY KEY,user_id INTEGER NOT NULL "
      "REFERENCES users(id),body TEXT NOT NULL CHECK(length(body) BETWEEN 1 "
      "AND 500),created_at TEXT NOT NULL "
      "DEFAULT(strftime('%Y-%m-%dT%H:%M:%fZ','now')));"
      "CREATE TABLE likes(user_id INTEGER NOT NULL REFERENCES "
      "users(id),post_id INTEGER NOT NULL REFERENCES posts(id),created_at TEXT "
      "NOT NULL DEFAULT(strftime('%Y-%m-%dT%H:%M:%fZ','now')),PRIMARY "
      "KEY(user_id,post_id));"
      "CREATE INDEX posts_created_at_id_idx ON posts(created_at DESC,id DESC);"
      "CREATE INDEX posts_user_id_idx ON posts(user_id);"
      "CREATE INDEX likes_post_id_idx ON likes(post_id);"
      "WITH RECURSIVE x(n) AS(VALUES(1) UNION ALL SELECT n+1 FROM x WHERE "
      "n<4096) INSERT INTO users(id,username) SELECT "
      "n,printf('training_user_%d',n) FROM x;"
      "WITH RECURSIVE x(n) AS(VALUES(1) UNION ALL SELECT n+1 FROM x WHERE "
      "n<20000) INSERT INTO posts(id,user_id,body,created_at) SELECT "
      "n,n%4096+1,printf('training post %d: text with quotes \" and Unicode "
      "café',n),'2020-01-01T00:00:00.000Z' FROM x;"
      "WITH RECURSIVE x(n) AS(VALUES(1) UNION ALL SELECT n+1 FROM x WHERE "
      "n<80000) INSERT OR IGNORE INTO likes(user_id,post_id) SELECT "
      "n%4096+1,(n*7919)%20000+1 FROM x; COMMIT;");
  sqlite3_close(d);
}
static size_t b64(const unsigned char *s, size_t n, char *out) {
  int len = EVP_EncodeBlock((unsigned char *)out, s, (int)n);
  while (len && out[len - 1] == '=')
    len--;
  for (int i = 0; i < len; i++) {
    if (out[i] == '+')
      out[i] = '-';
    else if (out[i] == '/')
      out[i] = '_';
  }
  out[len] = 0;
  return (size_t)len;
}
static void signed_token(char *out, size_t size) {
  char h[128], p[512], payload[256], msg[1024], sig[64];
  unsigned char digest[32];
  unsigned len;
  const char *header = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
  b64((const unsigned char *)header, strlen(header), h);
  snprintf(payload, sizeof payload,
           "{\"sub\":\"1\",\"username\":\"training_user_1\",\"exp\":%lld}",
           (long long)time(NULL) + 3600);
  b64((const unsigned char *)payload, strlen(payload), p);
  snprintf(msg, sizeof msg, "%s.%s", h, p);
  HMAC(EVP_sha256(), "training-only", 13, (const unsigned char *)msg,
       strlen(msg), digest, &len);
  b64(digest, len, sig);
  snprintf(out, size, "Bearer %s.%s", msg, sig);
}
static double cpu(void) {
  struct timespec t;
  clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &t);
  return t.tv_sec + t.tv_nsec * 1e-9;
}
int main(int argc, char **argv) {
  if (argc < 2)
    return 1;
  int bench = argc > 2;
  if (!bench)
    seed(argv[1]);
  if (!app_open(argv[1], "training-only"))
    return 1;
  char auth[1200];
  signed_token(auth, sizeof auth);
  Request req = {
      .method = "GET", .method_n = 3, .auth = auth, .auth_n = strlen(auth)};
  unsigned loops = bench ? 100000 : 40000;
  int ref = bench ? atoi(argv[2]) : 0;
  double start = cpu();
  uint64_t bytes = 0;
  for (unsigned i = 0; i < loops; i++) {
    char path[64];
    if (i % 100 < 50) {
      app_feed(&result, ref);
    } else if (!bench && i % 100 >= 92) {
      req.method = "POST";
      req.method_n = 4;
      if (i % 100 == 99) {
        req.path = "/posts";
        req.path_n = 6;
        req.body =
            "{\"body\":\"training create: \\\"quoted\\\" text and café\"}";
        req.body_n = strlen(req.body);
      } else {
        snprintf(path, sizeof path, "/posts/%u/like", i % 20000 + 1);
        req.path = path;
        req.path_n = strlen(path);
        req.body = "";
        req.body_n = 0;
      }
      app_handle(&req, &result);
    } else {
      snprintf(path, sizeof path, "/posts/%u", i % 20000 + 1);
      req.method = "GET";
      req.method_n = 3;
      req.path = path;
      req.path_n = strlen(path);
      app_handle(&req, &result);
    }
    if (result.status >= 500) {
      fprintf(stderr, "training request failed\n");
      return 1;
    }
    bytes += result.len;
    if (i % 64 == 63 && !app_commit())
      return 1;
  }
  if (!app_commit())
    return 1;
  printf("%s: %.3f us/request, %u requests, %llu serialized bytes\n",
         ref ? "reference SQL" : "range SQL", (cpu() - start) * 1e6 / loops,
         loops, (unsigned long long)bytes);
  app_close();
  return 0;
}
