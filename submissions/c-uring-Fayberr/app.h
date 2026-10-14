#pragma once
#include "sqlite3.h"
#include <stddef.h>
#include <stdint.h>

#define RESPONSE_MAX 65536
typedef struct {
  char data[RESPONSE_MAX];
  size_t len;
  int status;
} Response;
typedef struct {
  const char *method, *path, *auth, *body;
  size_t method_n, path_n, auth_n, body_n;
} Request;
int app_open(const char *path, const char *secret);
void app_close(void);
void app_handle(const Request *req, Response *out);
int app_commit(void);
int app_in_transaction(void);
void app_error(Response *out, int status, const char *message);
void app_feed(Response *out, int reference);
