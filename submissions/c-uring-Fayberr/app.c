#include "app.h"
#include "yyjson.h"
#include <limits.h>
#include <math.h>
#include <openssl/crypto.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static sqlite3 *db;
static sqlite3_stmt *ids, *counts, *rows, *feed, *one, *create, *like, *exists,
    *ping, *begin, *commit, *rollback;
static SHA256_CTX inner_key, outer_key;
static time_t started;
static int transaction, lost_transaction;
static const char post_sql[] =
    "SELECT p.id,p.body,p.created_at,u.username,(SELECT count(*) FROM likes l "
    "WHERE l.post_id=p.id) FROM posts p JOIN users u ON u.id=p.user_id ";

static sqlite3_stmt *prepare(const char *sql) {
  sqlite3_stmt *s = NULL;
  if (sqlite3_prepare_v3(db, sql, -1, SQLITE_PREPARE_PERSISTENT, &s, NULL) !=
      SQLITE_OK) {
    fprintf(stderr, "prepare: %s\n", sqlite3_errmsg(db));
    exit(1);
  }
  return s;
}

int app_open(const char *path, const char *secret) {
  if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_NOMUTEX,
                      NULL) != SQLITE_OK)
    return 0;
  if (sqlite3_exec(db,
                   "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA "
                   "locking_mode=EXCLUSIVE; PRAGMA foreign_keys=ON; PRAGMA "
                   "cache_size=-32768; PRAGMA mmap_size=536870912; PRAGMA "
                   "temp_store=MEMORY; PRAGMA busy_timeout=1000;",
                   NULL, NULL, NULL) != SQLITE_OK) {
    fprintf(stderr, "database: %s\n", sqlite3_errmsg(db));
    return 0;
  }
  ids =
      prepare("SELECT id FROM posts ORDER BY created_at DESC,id DESC LIMIT 20");
  counts = prepare("SELECT post_id,count(*) FROM likes WHERE post_id BETWEEN "
                   "?1 AND ?2 GROUP BY post_id ORDER BY post_id DESC");
  rows = prepare("SELECT p.id,p.body,p.created_at,u.username FROM posts p "
                 "CROSS JOIN users u ON u.id=p.user_id WHERE p.id BETWEEN ?1 "
                 "AND ?2 ORDER BY p.id DESC");
  char sql[512];
  snprintf(sql, sizeof sql, "%sORDER BY p.created_at DESC,p.id DESC LIMIT 20",
           post_sql);
  feed = prepare(sql);
  snprintf(sql, sizeof sql, "%sWHERE p.id=?1", post_sql);
  one = prepare(sql);
  create = prepare(
      "INSERT INTO posts(user_id,body) VALUES(?1,?2) RETURNING id,created_at");
  like = prepare("INSERT INTO likes(user_id,post_id) SELECT ?1,id FROM posts "
                 "WHERE id=?2 ON CONFLICT(user_id,post_id) DO NOTHING");
  exists = prepare("SELECT 1 FROM posts WHERE id=?1");
  ping = prepare("SELECT 1");
  begin = prepare("BEGIN IMMEDIATE");
  commit = prepare("COMMIT");
  rollback = prepare("ROLLBACK");
  unsigned char key[64] = {0}, pad[64];
  size_t n = strlen(secret);
  if (n > 64)
    SHA256((const unsigned char *)secret, n, key);
  else
    memcpy(key, secret, n);
  for (int i = 0; i < 64; i++)
    pad[i] = key[i] ^ 0x36;
  SHA256_Init(&inner_key);
  SHA256_Update(&inner_key, pad, 64);
  for (int i = 0; i < 64; i++)
    pad[i] = key[i] ^ 0x5c;
  SHA256_Init(&outer_key);
  SHA256_Update(&outer_key, pad, 64);
  OPENSSL_cleanse(key, sizeof key);
  OPENSSL_cleanse(pad, sizeof pad);
  started = time(NULL);
  return 1;
}

void app_close(void) {
  if (transaction)
    sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
  sqlite3_stmt *all[] = {ids,  counts, rows, feed,  one,    create,
                         like, exists, ping, begin, commit, rollback};
  for (size_t i = 0; i < sizeof all / sizeof all[0]; i++)
    sqlite3_finalize(all[i]);
  sqlite3_close(db);
  db = NULL;
}

static void put(Response *w, const char *p, size_t n) {
  if (n > RESPONSE_MAX - w->len) {
    w->status = 500;
    return;
  }
  memcpy(w->data + w->len, p, n);
  w->len += n;
}
#define LIT(w, s) put(w, s, sizeof(s) - 1)
static void integer(Response *w, int64_t x) {
  char b[24];
  char *p = b + sizeof b;
  uint64_t u = (uint64_t)x;
  if (x < 0)
    u = 0 - u;
  do {
    *--p = (char)('0' + u % 10);
    u /= 10;
  } while (u);
  if (x < 0)
    *--p = '-';
  put(w, p, (size_t)(b + sizeof b - p));
}
static uint64_t zero_byte(uint64_t x) {
  return (x - 0x0101010101010101ULL) & ~x & 0x8080808080808080ULL;
}
static void string(Response *w, const char *s, size_t n) {
  static const char hex[] = "0123456789abcdef";
  LIT(w, "\"");
  size_t i = 0, run = 0;
  while (i < n) {
    if (i + 8 <= n) {
      uint64_t x;
      memcpy(&x, s + i, 8);
      if (!zero_byte(x ^ 0x2222222222222222ULL) &&
          !zero_byte(x ^ 0x5c5c5c5c5c5c5c5cULL) &&
          !((x - 0x2020202020202020ULL) & ~x & 0x8080808080808080ULL)) {
        i += 8;
        continue;
      }
    }
    unsigned char c = (unsigned char)s[i];
    if (c == '"' || c == '\\' || c < 32) {
      put(w, s + run, i - run);
      if (c == '"' || c == '\\') {
        char e[2] = {'\\', (char)c};
        put(w, e, 2);
      } else {
        char e[6] = {'\\', 'u', '0', '0', hex[c >> 4], hex[c & 15]};
        put(w, e, 6);
      }
      run = i + 1;
    }
    i++;
  }
  put(w, s + run, n - run);
  LIT(w, "\"");
}
static void column(Response *w, sqlite3_stmt *s, int i) {
  string(w, (const char *)sqlite3_column_text(s, i),
         (size_t)sqlite3_column_bytes(s, i));
}
static void post_row(Response *w, sqlite3_stmt *s, int64_t likes) {
  LIT(w, "{\"id\":");
  integer(w, sqlite3_column_int64(s, 0));
  LIT(w, ",\"body\":");
  column(w, s, 1);
  LIT(w, ",\"created_at\":");
  column(w, s, 2);
  LIT(w, ",\"author\":");
  column(w, s, 3);
  LIT(w, ",\"like_count\":");
  integer(w, likes);
  LIT(w, "}");
}
void app_error(Response *w, int status, const char *message) {
  w->len = 0;
  w->status = status;
  LIT(w, "{\"error\":");
  string(w, message, strlen(message));
  LIT(w, "}");
}

void app_feed(Response *w, int reference) {
  int rc, n = 0;
  int64_t list[20];
  w->len = 0;
  w->status = 200;
  if (!reference) {
    while ((rc = sqlite3_step(ids)) == SQLITE_ROW)
      list[n++] = sqlite3_column_int64(ids, 0);
    sqlite3_reset(ids);
    if (rc != SQLITE_DONE)
      goto failed;
    for (int i = 1; i < n; i++)
      if (list[i] != list[0] - i)
        reference = 1;
  }
  LIT(w, "{\"posts\":[");
  if (reference) {
    n = 0;
    while ((rc = sqlite3_step(feed)) == SQLITE_ROW) {
      if (n++)
        LIT(w, ",");
      post_row(w, feed, sqlite3_column_int64(feed, 4));
    }
    sqlite3_reset(feed);
    if (rc != SQLITE_DONE)
      goto failed;
  } else if (n) {
    sqlite3_bind_int64(counts, 1, list[n - 1]);
    sqlite3_bind_int64(counts, 2, list[0]);
    sqlite3_bind_int64(rows, 1, list[n - 1]);
    sqlite3_bind_int64(rows, 2, list[0]);
    int lc = sqlite3_step(counts), i = 0;
    while ((rc = sqlite3_step(rows)) == SQLITE_ROW) {
      int64_t id = sqlite3_column_int64(rows, 0);
      while (lc == SQLITE_ROW && sqlite3_column_int64(counts, 0) > id)
        lc = sqlite3_step(counts);
      int64_t likes =
          (lc == SQLITE_ROW && sqlite3_column_int64(counts, 0) == id)
              ? sqlite3_column_int64(counts, 1)
              : 0;
      if (i++)
        LIT(w, ",");
      post_row(w, rows, likes);
    }
    if (lc == SQLITE_ROW)
      lc = sqlite3_step(counts);
    sqlite3_reset(rows);
    sqlite3_reset(counts);
    if (rc != SQLITE_DONE || lc != SQLITE_DONE)
      goto failed;
  }
  LIT(w, "]}");
  if (w->status == 500)
    goto failed;
  return;
failed:
  app_error(w, 500, "internal server error");
}

int app_in_transaction(void) { return transaction; }
static int ensure_transaction(void) {
  if (transaction && !sqlite3_get_autocommit(db))
    return 1;
  if (transaction)
    lost_transaction = 1;
  int rc = sqlite3_step(begin);
  sqlite3_reset(begin);
  transaction = (rc == SQLITE_DONE);
  return transaction;
}
int app_commit(void) {
  int ok = !lost_transaction;
  lost_transaction = 0;
  if (!transaction)
    return ok;
  transaction = 0;
  int rc = sqlite3_step(commit);
  sqlite3_reset(commit);
  if (rc == SQLITE_DONE)
    return ok;
  sqlite3_step(rollback);
  sqlite3_reset(rollback);
  return 0;
}

typedef struct {
  unsigned char data[32768];
  size_t used;
} Arena;
static void *arena_malloc(void *ctx, size_t n) {
  Arena *a = ctx;
  n = (n + 7) & ~(size_t)7;
  if (n > sizeof a->data - a->used)
    return NULL;
  void *p = a->data + a->used;
  a->used += n;
  return p;
}
static void arena_free(void *ctx, void *p) {
  (void)ctx;
  (void)p;
}
static void *arena_realloc(void *ctx, void *p, size_t old, size_t n) {
  void *q = arena_malloc(ctx, n);
  if (q && p)
    memcpy(q, p, old < n ? old : n);
  return q;
}
static yyjson_doc *json_read(Arena *a, const char *s, size_t n) {
  yyjson_alc alc = {arena_malloc, arena_realloc, arena_free, a};
  a->used = 0;
  return yyjson_read_opts((char *)s, n, 0, &alc, NULL);
}
static int64_t positive_id(const char *s, size_t n) {
  if (!n)
    return 0;
  uint64_t x = 0;
  for (size_t i = 0; i < n; i++) {
    unsigned c = (unsigned char)s[i] - '0';
    if (c > 9 || x > ((uint64_t)INT64_MAX - c) / 10)
      return 0;
    x = x * 10 + c;
  }
  return (int64_t)x;
}
static int decode64(const char *s, size_t n, unsigned char *out, size_t cap) {
  uint32_t v = 0;
  unsigned bits = 0;
  size_t j = 0;
  if (n % 4 == 1)
    return -1;
  for (size_t i = 0; i < n; i++) {
    unsigned c = (unsigned char)s[i], a;
    if (c >= 'A' && c <= 'Z')
      a = c - 'A';
    else if (c >= 'a' && c <= 'z')
      a = c - 'a' + 26;
    else if (c >= '0' && c <= '9')
      a = c - '0' + 52;
    else if (c == '-')
      a = 62;
    else if (c == '_')
      a = 63;
    else
      return -1;
    v = (v << 6) | a;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      if (j == cap)
        return -1;
      out[j++] = (unsigned char)(v >> bits);
    }
  }
  if (bits && (v & ((1u << bits) - 1)))
    return -1;
  return (int)j;
}
typedef struct {
  int64_t id;
  char name[16384];
  size_t name_n;
} User;
static int authenticate(const Request *r, User *u) {
  if (r->auth_n < 7 || memcmp(r->auth, "Bearer ", 7))
    return 1;
  const char *s = r->auth + 7;
  size_t n = r->auth_n - 7;
  const char *a = memchr(s, '.', n);
  if (!a)
    return 2;
  const char *b = memchr(a + 1, '.', n - (size_t)(a + 1 - s));
  if (!b)
    return 2;
  unsigned char sig[32], digest[32], buf[16384];
  int sn = decode64(b + 1, n - (size_t)(b + 1 - s), sig, sizeof sig);
  if (sn != 32)
    return 2;
  SHA256_CTX inner = inner_key, outer = outer_key;
  SHA256_Update(&inner, s, (size_t)(b - s));
  SHA256_Final(digest, &inner);
  SHA256_Update(&outer, digest, 32);
  SHA256_Final(digest, &outer);
  if (CRYPTO_memcmp(sig, digest, 32))
    return 2;
  int h = decode64(s, (size_t)(a - s), buf, sizeof buf);
  if (h < 0)
    return 2;
  Arena arena;
  yyjson_doc *doc = json_read(&arena, (char *)buf, (size_t)h);
  if (!doc)
    return 2;
  yyjson_val *root = yyjson_doc_get_root(doc),
             *alg = yyjson_obj_get(root, "alg");
  if (!yyjson_is_str(alg) || yyjson_get_len(alg) != 5 ||
      memcmp(yyjson_get_str(alg), "HS256", 5))
    return 2;
  int p = decode64(a + 1, (size_t)(b - a - 1), buf, sizeof buf);
  if (p < 0)
    return 2;
  doc = json_read(&arena, (char *)buf, (size_t)p);
  if (!doc)
    return 2;
  root = yyjson_doc_get_root(doc);
  yyjson_val *exp = yyjson_obj_get(root, "exp"),
             *nbf = yyjson_obj_get(root, "nbf");
  double now = (double)time(NULL);
  if (!yyjson_is_num(exp) || !isfinite(yyjson_get_num(exp)) ||
      yyjson_get_num(exp) <= now)
    return 2;
  if (nbf && (!yyjson_is_num(nbf) || !isfinite(yyjson_get_num(nbf)) ||
              yyjson_get_num(nbf) > now))
    return 2;
  yyjson_val *sub = yyjson_obj_get(root, "sub"),
             *name = yyjson_obj_get(root, "username");
  if (!yyjson_is_str(sub) ||
      !(u->id = positive_id(yyjson_get_str(sub), yyjson_get_len(sub))) ||
      !yyjson_is_str(name))
    return 3;
  u->name_n = yyjson_get_len(name);
  if (u->name_n > sizeof u->name)
    return 3;
  memcpy(u->name, yyjson_get_str(name), u->name_n);
  return 0;
}
static size_t utf8(const char *s, size_t n, uint32_t *cp) {
  unsigned char a = (unsigned char)s[0];
  size_t len;
  if (a < 128) {
    *cp = a;
    return 1;
  }
  if (a < 0xe0) {
    *cp = a & 31;
    len = 2;
  } else if (a < 0xf0) {
    *cp = a & 15;
    len = 3;
  } else {
    *cp = a & 7;
    len = 4;
  }
  if (len > n)
    return 0;
  for (size_t i = 1; i < len; i++)
    *cp = (*cp << 6) | ((unsigned char)s[i] & 63);
  return len;
}
static int whitespace(uint32_t c) {
  return (c >= 9 && c <= 13) || c == 32 || c == 0xa0 || c == 0x1680 ||
         (c >= 0x2000 && c <= 0x200a) || c == 0x2028 || c == 0x2029 ||
         c == 0x202f || c == 0x205f || c == 0x3000 || c == 0xfeff;
}
static int equal(const char *s, size_t n, const char *literal, size_t m) {
  return n == m && !memcmp(s, literal, m);
}
#define EQ(s, n, l) equal(s, n, l, sizeof(l) - 1)
void app_handle(const Request *r, Response *w) {
  w->len = 0;
  w->status = 200;
  yyjson_doc *body_doc = NULL;
  int get = EQ(r->method, r->method_n, "GET"),
      post = EQ(r->method, r->method_n, "POST");
  if (get && EQ(r->path, r->path_n, "/feed")) {
    app_feed(w, 0);
    return;
  }
  if (get && EQ(r->path, r->path_n, "/health")) {
    int rc = sqlite3_step(ping);
    sqlite3_reset(ping);
    if (rc == SQLITE_ROW) {
      LIT(w, "{\"status\":\"ok\",\"db\":\"ok\",\"uptime_s\":");
      integer(w, time(NULL) - started);
      LIT(w, "}");
    } else {
      w->status = 503;
      LIT(w, "{\"status\":\"degraded\",\"db\":\"unreachable\",\"error\":");
      string(w, sqlite3_errmsg(db), strlen(sqlite3_errmsg(db)));
      LIT(w, "}");
    }
    return;
  }
  int is_create = post && EQ(r->path, r->path_n, "/posts");
  int is_like = post && r->path_n > 12 && !memcmp(r->path, "/posts/", 7) &&
                !memcmp(r->path + r->path_n - 5, "/like", 5);
  int is_one = get && r->path_n >= 7 && !memcmp(r->path, "/posts/", 7);
  if (!is_create && !is_like && !is_one) {
    app_error(w, 404, "not found");
    return;
  }
  User user;
  if (post) {
    int auth = authenticate(r, &user);
    if (auth) {
      app_error(w, 401,
                auth == 1   ? "missing bearer token"
                : auth == 2 ? "invalid or expired token"
                            : "invalid token payload");
      return;
    }
  }
  int64_t id = 0;
  if (!is_create) {
    id = positive_id(r->path + 7, r->path_n - 7 - (is_like ? 5 : 0));
    if (!id) {
      app_error(w, 400, "invalid post id");
      return;
    }
  }
  if (is_one) {
    sqlite3_bind_int64(one, 1, id);
    int rc = sqlite3_step(one);
    if (rc == SQLITE_ROW) {
      LIT(w, "{\"post\":");
      post_row(w, one, sqlite3_column_int64(one, 4));
      LIT(w, "}");
    }
    sqlite3_reset(one);
    if (rc != SQLITE_ROW)
      app_error(w, rc == SQLITE_DONE ? 404 : 500,
                rc == SQLITE_DONE ? "post not found" : "internal server error");
    return;
  }
  if (is_like) {
    if (!ensure_transaction())
      goto failed;
    sqlite3_bind_int64(like, 1, user.id);
    sqlite3_bind_int64(like, 2, id);
    int rc = sqlite3_step(like);
    sqlite3_reset(like);
    if (rc != SQLITE_DONE)
      goto failed;
    int changed = sqlite3_changes(db);
    if (!changed) {
      sqlite3_bind_int64(exists, 1, id);
      rc = sqlite3_step(exists);
      sqlite3_reset(exists);
      if (rc != SQLITE_ROW) {
        app_error(w, rc == SQLITE_DONE ? 404 : 500,
                  rc == SQLITE_DONE ? "post not found"
                                    : "internal server error");
        return;
      }
    }
    w->status = changed ? 201 : 200;
    LIT(w, "{\"liked\":true,\"already_liked\":");
    if (changed)
      LIT(w, "false");
    else
      LIT(w, "true");
    LIT(w, ",\"post_id\":");
    integer(w, id);
    LIT(w, "}");
    return;
  }
  Arena arena;
  body_doc = json_read(&arena, r->body, r->body_n);
  if (!body_doc)
    body_doc = yyjson_read(r->body, r->body_n, 0);
  if (!body_doc) {
    yyjson_doc_free(body_doc);
    app_error(w, 400, "malformed JSON body");
    return;
  }
  yyjson_val *body = yyjson_obj_get(yyjson_doc_get_root(body_doc), "body");
  if (!yyjson_is_str(body)) {
    yyjson_doc_free(body_doc);
    app_error(w, 400, "body is required");
    return;
  }
  const char *s = yyjson_get_str(body);
  size_t n = yyjson_get_len(body), i = 0, first = n, last = 0, chars = 0,
         last_chars = 0;
  while (i < n) {
    uint32_t cp;
    size_t len = utf8(s + i, n - i, &cp);
    if (!len) {
      yyjson_doc_free(body_doc);
      app_error(w, 400, "malformed JSON body");
      return;
    }
    if (!whitespace(cp)) {
      if (first == n)
        first = i;
      last = i + len;
      last_chars = chars + 1;
    }
    if (first != n)
      chars++;
    i += len;
  }
  if (first == n) {
    yyjson_doc_free(body_doc);
    app_error(w, 400, "body is required");
    return;
  }
  if (last_chars > 500) {
    yyjson_doc_free(body_doc);
    app_error(w, 400, "body must be at most 500 characters");
    return;
  }
  if (!ensure_transaction())
    goto failed;
  sqlite3_bind_int64(create, 1, user.id);
  sqlite3_bind_text(create, 2, s + first, (int)(last - first), SQLITE_STATIC);
  int rc = sqlite3_step(create);
  if (rc == SQLITE_ROW) {
    w->status = 201;
    LIT(w, "{\"post\":{\"id\":");
    integer(w, sqlite3_column_int64(create, 0));
    LIT(w, ",\"body\":");
    string(w, s + first, last - first);
    LIT(w, ",\"created_at\":");
    column(w, create, 1);
    LIT(w, ",\"author\":");
    string(w, user.name, user.name_n);
    LIT(w, ",\"like_count\":0}}");
    rc = sqlite3_step(create);
  }
  sqlite3_reset(create);
  if (rc != SQLITE_DONE)
    goto failed;
  yyjson_doc_free(body_doc);
  return;
failed:
  yyjson_doc_free(body_doc);
  app_error(w, 500, "internal server error");
}
