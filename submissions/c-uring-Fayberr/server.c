#define _GNU_SOURCE
#include "app.h"
#include "picohttpparser.h"
#include <arpa/inet.h>
#include <errno.h>
#include <liburing.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#ifndef BATCH_NS
#define BATCH_NS 8000000
#endif
#ifndef BATCH_MIN
#define BATCH_MIN 256
#endif
enum {
  MAX_RINGS = 8,
  SLOTS = 65000,
  NBUFS = 2048,
  BUFSIZE = 4096,
  INPUT_MAX = 36864,
  QUEUE = 4096
};
enum { OP_ACCEPT = 1, OP_RECV, OP_SEND, OP_CLOSE, OP_CANCEL };
typedef struct Block {
  struct Block *next;
  unsigned bucket;
  char bytes[];
} Block;
static Block *free_blocks[4];
static unsigned free_count[4];
static const size_t capacities[] = {4096, 16384, 65536, 131072};
static char *allocate(size_t n) {
  unsigned i = 0;
  while (i < 3 && capacities[i] < n)
    i++;
  if (n > capacities[i])
    return NULL;
  Block *b = free_blocks[i];
  if (b) {
    free_blocks[i] = b->next;
    free_count[i]--;
  } else {
    b = malloc(sizeof(*b) + capacities[i]);
    if (!b)
      return NULL;
    b->bucket = i;
  }
  return b->bytes;
}
static Block *block(char *p) { return (Block *)(p - offsetof(Block, bytes)); }
static void release(char *p) {
  if (!p)
    return;
  Block *b = block(p);
  unsigned i = b->bucket;
  if (free_count[i] < 256) {
    b->next = free_blocks[i];
    free_blocks[i] = b;
    free_count[i]++;
  } else
    free(b);
}
static size_t capacity(char *p) { return capacities[block(p)->bucket]; }

typedef struct Conn {
  char *input, *output;
  uint32_t input_n, output_n, sent, generation;
  uint32_t last_activity;
  unsigned active : 1, receiving : 1, sending : 1, closing : 1, close_armed : 1,
      queued : 1, close_after : 1, continued : 1, read_eof : 1;
  struct Conn *next;
} Conn;
typedef struct {
  struct io_uring ring;
  struct io_uring_buf_ring *br;
  char *buffers;
  Conn *connections;
  unsigned index;
  unsigned accepting, used;
  unsigned full : 1;
} Worker;
static Worker workers[MAX_RINGS];
static unsigned nrings;
static unsigned file_slots;
static int listener;
static int accepting_paused, trim_idle;
static unsigned long long memory_limit;
static char memory_current_path[1280];
static void memory_init(void) {
  FILE *f = fopen("/proc/self/cgroup", "r");
  char line[1200], path[1024];
  if (!f)
    return;
  while (fgets(line, sizeof line, f))
    if (sscanf(line, "0::%1023[^\n]", path) == 1) {
      char file[1280];
      snprintf(file, sizeof file, "/sys/fs/cgroup%s/memory.max", path);
      FILE *limit = fopen(file, "r");
      if (limit) {
        if (fscanf(limit, "%llu", &memory_limit) != 1)
          memory_limit = 0;
        fclose(limit);
      }
      if (memory_limit)
        snprintf(memory_current_path, sizeof memory_current_path,
                 "/sys/fs/cgroup%s/memory.current", path);
      break;
    }
  fclose(f);
}
static unsigned long long memory_available(void) {
  unsigned long long used = 0;
  if (memory_limit) {
    FILE *f = fopen(memory_current_path, "r");
    if (f) {
      int ok = fscanf(f, "%llu", &used);
      fclose(f);
      if (ok == 1)
        return used < memory_limit ? memory_limit - used : 0;
    }
  }
  FILE *f = fopen("/proc/meminfo", "r");
  char line[256];
  unsigned long long available = ~0ULL;
  if (f) {
    while (fgets(line, sizeof line, f))
      if (sscanf(line, "MemAvailable: %llu kB", &used) == 1) {
        available = used * 1024;
        break;
      }
    fclose(f);
  }
  return available;
}
static Conn *pending;
static Response response;
static volatile sig_atomic_t stopping;
static uint32_t tick;
static void signal_stop(int sig) {
  (void)sig;
  stopping = 1;
}
static uint32_t clock_seconds(void) {
  struct timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  return (uint32_t)t.tv_sec;
}
static uint64_t tag(unsigned op, unsigned index, uint32_t generation) {
  return ((uint64_t)generation << 32) | ((uint64_t)index << 8) | op;
}
static unsigned conn_index(Worker *w, Conn *c) {
  return (unsigned)(c - w->connections);
}
static struct io_uring_sqe *sqe(Worker *w) {
  struct io_uring_sqe *s = io_uring_get_sqe(&w->ring);
  if (!s) {
    int rc = io_uring_submit(&w->ring);
    if (rc < 0) {
      fprintf(stderr, "submit: %s\n", strerror(-rc));
      exit(1);
    }
    s = io_uring_get_sqe(&w->ring);
  }
  if (!s) {
    fprintf(stderr, "submission queue exhausted\n");
    exit(1);
  }
  return s;
}
static void receive(Worker *w, Conn *c) {
  if (c->receiving || c->closing || c->read_eof || !c->active)
    return;
  struct io_uring_sqe *s = sqe(w);
  io_uring_prep_recv_multishot(s, (int)conn_index(w, c), NULL, 0, 0);
  s->flags = IOSQE_FIXED_FILE | IOSQE_BUFFER_SELECT;
  s->buf_group = 0;
  s->user_data = tag(OP_RECV, conn_index(w, c), c->generation);
  c->receiving = 1;
}
static void maybe_close(Worker *w, Conn *c) {
  if (!c->closing || c->receiving || c->sending || c->close_armed || c->queued)
    return;
  release(c->input);
  c->input = NULL;
  release(c->output);
  c->output = NULL;
  struct io_uring_sqe *s = sqe(w);
  io_uring_prep_close_direct(s, conn_index(w, c));
  s->user_data = tag(OP_CLOSE, conn_index(w, c), c->generation);
  c->close_armed = 1;
}
static void close_connection(Worker *w, Conn *c) {
  if (!c->active)
    return;
  if (!c->closing) {
    c->closing = 1;
    if (c->receiving) {
      struct io_uring_sqe *s = sqe(w);
      io_uring_prep_cancel64(s, tag(OP_RECV, conn_index(w, c), c->generation),
                             0);
      s->user_data = tag(OP_CANCEL, conn_index(w, c), c->generation);
    }
    if (c->sending) {
      struct io_uring_sqe *s = sqe(w);
      io_uring_prep_cancel64(s, tag(OP_SEND, conn_index(w, c), c->generation),
                             0);
      s->user_data = tag(OP_CANCEL, conn_index(w, c), c->generation);
    }
  }
  maybe_close(w, c);
}
static void send_output(Worker *w, Conn *c) {
  if (c->closing) {
    maybe_close(w, c);
    return;
  }
  if (!c->output || c->sending)
    return;
  struct io_uring_sqe *s = sqe(w);
  io_uring_prep_send(s, (int)conn_index(w, c), c->output + c->sent,
                     c->output_n - c->sent, MSG_NOSIGNAL);
  s->flags = IOSQE_FIXED_FILE;
  s->user_data = tag(OP_SEND, conn_index(w, c), c->generation);
  c->sending = 1;
}
static Worker *owner(Conn *c) {
  uintptr_t a = (uintptr_t)c;
  for (unsigned i = 0; i < nrings; i++) {
    uintptr_t b = (uintptr_t)workers[i].connections;
    if (a >= b && a < b + sizeof(Conn) * file_slots)
      return &workers[i];
  }
  abort();
}
static void format_output(Worker *w, Conn *c, Response *r) {
  if (r->status == 500)
    app_error(r, 500, "internal server error");
  const char *prefix;
  size_t prefix_n;
#define PREFIX(text)                                                           \
  do {                                                                         \
    prefix = text;                                                             \
    prefix_n = sizeof(text) - 1;                                               \
  } while (0)
  switch (r->status) {
  case 200:
    PREFIX("HTTP/1.1 200 OK\r\nContent-Type: "
           "application/json\r\nContent-Length: ");
    break;
  case 201:
    PREFIX("HTTP/1.1 201 Created\r\nContent-Type: "
           "application/json\r\nContent-Length: ");
    break;
  case 400:
    PREFIX("HTTP/1.1 400 Bad Request\r\nContent-Type: "
           "application/json\r\nContent-Length: ");
    break;
  case 401:
    PREFIX("HTTP/1.1 401 Unauthorized\r\nContent-Type: "
           "application/json\r\nContent-Length: ");
    break;
  case 404:
    PREFIX("HTTP/1.1 404 Not Found\r\nContent-Type: "
           "application/json\r\nContent-Length: ");
    break;
  case 503:
    PREFIX("HTTP/1.1 503 Service Unavailable\r\nContent-Type: "
           "application/json\r\nContent-Length: ");
    break;
  default:
    PREFIX("HTTP/1.1 500 Internal Server Error\r\nContent-Type: "
           "application/json\r\nContent-Length: ");
    break;
  }
#undef PREFIX
  char header[256], digits[24];
  char *d = digits + sizeof digits;
  size_t length = r->len;
  do {
    *--d = (char)('0' + length % 10);
    length /= 10;
  } while (length);
  size_t digits_n = (size_t)(digits + sizeof digits - d);
  memcpy(header, prefix, prefix_n);
  memcpy(header + prefix_n, d, digits_n);
  const char *suffix = c->close_after ? "\r\nConnection: close\r\n\r\n"
                                      : "\r\nConnection: keep-alive\r\n\r\n";
  size_t suffix_n = c->close_after ? 23 : 28;
  memcpy(header + prefix_n + digits_n, suffix, suffix_n);
  size_t n = prefix_n + digits_n + suffix_n;
  c->output = allocate((size_t)n + r->len);
  if (!c->output) {
    close_connection(w, c);
    return;
  }
  memcpy(c->output, header, (size_t)n);
  memcpy(c->output + n, r->data, r->len);
  c->output_n = (uint32_t)((size_t)n + r->len);
  c->sent = 0;
}
static void queue_output(Worker *w, Conn *c, Response *r) {
  format_output(w, c, r);
  if (c->closing)
    return;
  c->queued = 1;
  c->next = pending;
  pending = c;
}
static int append_input(Worker *w, Conn *c, const char *data, size_t n) {
  if (n > INPUT_MAX - c->input_n) {
    close_connection(w, c);
    return 0;
  }
  if (!c->input || capacity(c->input) < c->input_n + n) {
    char *p = allocate(c->input_n + n);
    if (!p) {
      close_connection(w, c);
      return 0;
    }
    if (c->input_n)
      memcpy(p, c->input, c->input_n);
    release(c->input);
    c->input = p;
  }
  memcpy(c->input + c->input_n, data, n);
  c->input_n += (uint32_t)n;
  return 1;
}
static int header_equal(const char *s, size_t n, const char *name) {
  return s && n == strlen(name) && !strncasecmp(s, name, n);
}
static int decimal(const char *s, size_t n, size_t *out) {
  if (!n)
    return 0;
  size_t value = 0;
  for (size_t i = 0; i < n; i++) {
    unsigned d = (unsigned char)s[i] - '0';
    if (d > 9 || value > (SIZE_MAX - d) / 10)
      return 0;
    value = value * 10 + d;
  }
  *out = value;
  return 1;
}
/* Returns consumed wire bytes, 0 for incomplete input, -1 after a framing
 * error. */
static ssize_t handle(Worker *w, Conn *c, const char *data, size_t n) {
  Request r = {0};
  struct phr_header headers[64];
  size_t nh = 64;
  int minor;
  int h = phr_parse_request(data, n, &r.method, &r.method_n, &r.path, &r.path_n,
                            &minor, headers, &nh, 0);
  if (h == -2)
    return 0;
  if (h < 0)
    goto malformed;
  size_t length = 0;
  int cl = 0, chunked = 0, expect = 0;
  c->close_after = minor == 0;
  for (size_t i = 0; i < nh; i++) {
    struct phr_header *p = &headers[i];
    if (!p->name)
      goto malformed;
    if (header_equal(p->name, p->name_len, "Content-Length")) {
      size_t v;
      if (!decimal(p->value, p->value_len, &v) || (cl && length != v))
        goto malformed;
      length = v;
      cl = 1;
    } else if (header_equal(p->name, p->name_len, "Transfer-Encoding")) {
      if (chunked || !header_equal(p->value, p->value_len, "chunked"))
        goto malformed;
      chunked = 1;
    } else if (header_equal(p->name, p->name_len, "Authorization")) {
      if (r.auth)
        goto malformed;
      r.auth = p->value;
      r.auth_n = p->value_len;
    } else if (header_equal(p->name, p->name_len, "Connection")) {
      if (header_equal(p->value, p->value_len, "close"))
        c->close_after = 1;
      else if (header_equal(p->value, p->value_len, "keep-alive"))
        c->close_after = 0;
    } else if (header_equal(p->name, p->name_len, "Expect")) {
      if (!header_equal(p->value, p->value_len, "100-continue"))
        goto malformed;
      expect = 1;
    }
  }
  if (cl && chunked)
    goto malformed;
  if (length > INPUT_MAX - (size_t)h)
    goto malformed;
  r.body = data + h;
  r.body_n = length;
  size_t consumed = (size_t)h + length;
  char chunk_body[INPUT_MAX];
  if (chunked) {
    size_t decoded = n - (size_t)h;
    if (decoded > sizeof chunk_body)
      goto malformed;
    memcpy(chunk_body, data + h, decoded);
    struct phr_chunked_decoder decoder = {0};
    decoder.consume_trailer = 1;
    ssize_t remaining = phr_decode_chunked(&decoder, chunk_body, &decoded);
    if (remaining == -1)
      goto malformed;
    if (remaining == -2)
      goto incomplete;
    consumed = n - (size_t)remaining;
    r.body = chunk_body;
    r.body_n = decoded;
  } else if (n < consumed)
    goto incomplete;
  c->continued = 0;
  app_handle(&r, &response);
  queue_output(w, c, &response);
  return (ssize_t)consumed;
incomplete:
  if (expect && !c->continued) {
    static const char interim[] = "HTTP/1.1 100 Continue\r\n\r\n";
    c->output = allocate(sizeof interim - 1);
    if (!c->output) {
      close_connection(w, c);
      return -1;
    }
    memcpy(c->output, interim, sizeof interim - 1);
    c->output_n = sizeof interim - 1;
    c->sent = 0;
    c->continued = 1;
    send_output(w, c);
  }
  return 0;
malformed:
  c->close_after = 1;
  app_error(&response, 400, "malformed HTTP request");
  queue_output(w, c, &response);
  return -1;
}
static void process_input(Worker *w, Conn *c) {
  if (c->closing || c->output || !c->input_n)
    return;
  ssize_t used = handle(w, c, c->input, c->input_n);
  if (used > 0) {
    c->input_n -= (uint32_t)used;
    if (c->input_n)
      memmove(c->input, c->input + used, c->input_n);
  } else if (used < 0)
    c->input_n = 0;
  if (!c->input_n) {
    release(c->input);
    c->input = NULL;
  }
}
static void consume(Worker *w, Conn *c, const char *data, size_t n) {
  c->last_activity = tick;
  if (c->input_n || c->output) {
    if (append_input(w, c, data, n))
      process_input(w, c);
    return;
  }
  ssize_t used = handle(w, c, data, n);
  if (!used)
    append_input(w, c, data, n);
  else if (used > 0 && (size_t)used < n)
    append_input(w, c, data + used, n - (size_t)used);
}
static void flush(void) {
  int ok = app_commit();
  Conn *c = pending;
  pending = NULL;
  while (c) {
    Conn *next = c->next;
    Worker *w = owner(c);
    c->queued = 0;
    if (!ok && !c->closing) {
      release(c->output);
      c->output = NULL;
      app_error(&response, 500, "internal server error");
      format_output(w, c, &response);
    }
    send_output(w, c);
    c = next;
  }
  pending = NULL;
}
static void accept_arm(Worker *w) {
  if (w->full || accepting_paused)
    return;
  /* Reserve slots before accepting: allocating after accept can reset a client
     when a multishot accept exhausts the registered table. */
  unsigned window = file_slots / 4;
  if (window > 512)
    window = 512;
  while (w->accepting < window && w->used + w->accepting < file_slots) {
    struct io_uring_sqe *s = sqe(w);
    io_uring_prep_accept_direct(s, listener, NULL, NULL, SOCK_NONBLOCK,
                                IORING_FILE_INDEX_ALLOC);
    s->user_data = OP_ACCEPT;
    w->accepting++;
  }
}
static int init_ring(void) {
  if (nrings == MAX_RINGS)
    return 0;
  Worker *w = &workers[nrings];
  struct io_uring_params p = {0};
  p.flags = IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN |
            IORING_SETUP_TASKRUN_FLAG | IORING_SETUP_CQSIZE;
  p.cq_entries = QUEUE * 8;
  int rc = io_uring_queue_init_params(QUEUE, &w->ring, &p);
  if (rc < 0) {
    fprintf(stderr,
            "io_uring setup: %s (Linux >=6.1, io_uring enabled required)\n",
            strerror(-rc));
    return 0;
  }
  rc = io_uring_register_files_sparse(&w->ring, file_slots);
  if (rc < 0) {
    fprintf(stderr, "file table: %s\n", strerror(-rc));
    io_uring_queue_exit(&w->ring);
    return 0;
  }
  w->br = io_uring_setup_buf_ring(&w->ring, NBUFS, 0, 0, &rc);
  if (!w->br) {
    fprintf(stderr, "buffer ring: %s\n", strerror(-rc));
    io_uring_queue_exit(&w->ring);
    return 0;
  }
  w->buffers = mmap(NULL, (size_t)NBUFS * BUFSIZE, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  w->connections = calloc(file_slots, sizeof(Conn));
  if (w->buffers == MAP_FAILED || !w->connections)
    return 0;
  for (int i = 0; i < NBUFS; i++)
    io_uring_buf_ring_add(w->br, w->buffers + (size_t)i * BUFSIZE, BUFSIZE, i,
                          NBUFS - 1, i);
  io_uring_buf_ring_advance(w->br, NBUFS);
  w->index = nrings++;
  accept_arm(w);
  return 1;
}
static void completion(Worker *w, struct io_uring_cqe *q) {
  unsigned op = q->user_data & 255, index = (q->user_data >> 8) & 0xffffff;
  uint32_t gen = q->user_data >> 32;
  int more = q->flags & IORING_CQE_F_MORE;
  if (op == OP_ACCEPT) {
    w->accepting--;
    if (q->res >= 0) {
      w->used++;
      Conn *c = &w->connections[q->res];
      uint32_t generation = c->generation + 1;
      memset(c, 0, sizeof(*c));
      c->generation = generation;
      c->active = 1;
      c->last_activity = tick;
      receive(w, c);
    } else if (q->res != -ECANCELED && q->res != -EAGAIN && q->res != -EINTR) {
      fprintf(stderr, "accept: %s\n", strerror(-q->res));
      stopping = 1;
    }
    accept_arm(w);
    if (w->used + w->accepting == file_slots && !w->full) {
      w->full = 1;
      if (w->index == nrings - 1 && nrings < MAX_RINGS)
        init_ring();
    }
    return;
  }
  if (index >= file_slots)
    return;
  Conn *c = &w->connections[index];
  if (op == OP_RECV) {
    unsigned bid = q->flags >> IORING_CQE_BUFFER_SHIFT;
    if (c->active && c->generation == gen) {
      if (!more)
        c->receiving = 0;
      if (q->res > 0 && !c->closing)
        consume(w, c, w->buffers + (size_t)bid * BUFSIZE, (size_t)q->res);
      else if (q->res == 0 && !c->closing) {
        c->read_eof = 1;
        if (!c->output) {
          process_input(w, c);
          if (!c->output)
            close_connection(w, c);
        }
      } else if (q->res < 0 && q->res != -ENOBUFS && q->res != -ECANCELED &&
                 q->res != -EAGAIN)
        close_connection(w, c);
      if (c->closing)
        maybe_close(w, c);
      else if (!more)
        receive(w, c);
    }
    if (q->flags & IORING_CQE_F_BUFFER) {
      io_uring_buf_ring_add(w->br, w->buffers + (size_t)bid * BUFSIZE, BUFSIZE,
                            bid, NBUFS - 1, 0);
      io_uring_buf_ring_advance(w->br, 1);
    }
    return;
  }
  if (!c->active || c->generation != gen)
    return;
  if (op == OP_SEND) {
    c->sending = 0;
    if (c->closing) {
      maybe_close(w, c);
      return;
    }
    if (q->res <= 0) {
      close_connection(w, c);
      return;
    }
    c->last_activity = tick;
    c->sent += (uint32_t)q->res;
    if (c->sent < c->output_n)
      send_output(w, c);
    else {
      release(c->output);
      c->output = NULL;
      c->output_n = c->sent = 0;
      if (c->close_after)
        close_connection(w, c);
      else {
        process_input(w, c);
        if (c->read_eof && !c->output)
          close_connection(w, c);
        else
          receive(w, c);
      }
    }
  } else if (op == OP_CLOSE) {
    if (q->res < 0) {
      fprintf(stderr, "close: %s\n", strerror(-q->res));
      stopping = 1;
    }
    c->active = 0;
    c->close_armed = 0;
    w->used--;
    /* A full older table can accept again if the newest table also filled. */
    if (w->full && workers[nrings - 1].full) {
      w->full = 0;
      accept_arm(w);
    }
  }
}
static unsigned drain(Worker *w) {
  struct io_uring_cqe *q;
  unsigned head, count = 0;
  io_uring_for_each_cqe(&w->ring, head, q) {
    completion(w, q);
    count++;
    if (count == QUEUE * 4)
      break;
  }
  io_uring_cq_advance(&w->ring, count);
  return count;
}
int main(void) {
  const char *path = getenv("SQLITE_PATH"), *secret = getenv("JWT_SECRET"),
             *host = getenv("HOST"), *port = getenv("PORT");
  if (!path || !secret || !host || !port) {
    fprintf(stderr, "SQLITE_PATH, JWT_SECRET, HOST and PORT are required\n");
    return 1;
  }
  size_t port_value;
  if (!decimal(port, strlen(port), &port_value) || !port_value ||
      port_value > 65535)
    return 1;
  struct rlimit limit;
  getrlimit(RLIMIT_NOFILE, &limit);
  file_slots = limit.rlim_cur > SLOTS ? SLOTS : (unsigned)limit.rlim_cur;
  if (file_slots < 128) {
    fprintf(stderr, "nofile limit too small\n");
    return 1;
  }
  signal(SIGINT, signal_stop);
  signal(SIGTERM, signal_stop);
  signal(SIGPIPE, SIG_IGN);
  listener = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  if (listener < 0) {
    perror("socket");
    return 1;
  }
  int yes = 1;
  setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);
  setsockopt(listener, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof yes);
  struct sockaddr_in addr = {.sin_family = AF_INET,
                             .sin_port = htons((uint16_t)port_value)};
  if (inet_pton(AF_INET, host, &addr.sin_addr) != 1 ||
      bind(listener, (struct sockaddr *)&addr, sizeof addr) ||
      listen(listener, 4096)) {
    perror("listen");
    return 1;
  }
  if (!app_open(path, secret) || !init_ring())
    return 1;
  memory_init();
  tick = clock_seconds();
  uint32_t last_scan = tick, last_memory = tick;
  unsigned recent = 0, scan_ring = 0, scan_index = 0;
  fprintf(stderr, "direct HTTP %s:%s; SQLite %s; %u registered slots/ring\n",
          host, port, sqlite3_libversion(), file_slots);
  while (!stopping) {
    unsigned completed = 0;
    for (unsigned i = 0; i < nrings; i++)
      completed += drain(&workers[i]);
    if (pending)
      flush();
    /* A submit alone can starve deferred receives in busy secondary rings. */
    for (unsigned i = 1; i < nrings; i++) {
      struct __kernel_timespec zero = {0, 0};
      struct io_uring_cqe *unused = NULL;
      int rc = io_uring_submit_and_wait_timeout(&workers[i].ring, &unused,
                                                BATCH_MIN, &zero, NULL);
      if (rc < 0 && rc != -EINTR && rc != -ETIME && rc != -EAGAIN) {
        fprintf(stderr, "submit: %s\n", strerror(-rc));
        stopping = 1;
      }
    }
    struct __kernel_timespec timeout = {
        .tv_sec = 0, .tv_nsec = recent >= 4 ? BATCH_NS : 10000000};
    struct io_uring_cqe *q = NULL;
    unsigned ready = io_uring_cq_ready(&workers[0].ring);
    unsigned want = recent >= 4 ? BATCH_MIN : 1;
    if (ready < want) {
      int rc = io_uring_submit_and_wait_timeout(&workers[0].ring, &q, want,
                                                &timeout, NULL);
      if (rc < 0 && rc != -ETIME && rc != -EINTR) {
        fprintf(stderr, "wait: %s\n", strerror(-rc));
        stopping = 1;
      }
    } else {
      int rc = io_uring_submit(&workers[0].ring);
      if (rc < 0 && rc != -EINTR)
        stopping = 1;
    }
    recent = completed;
    tick = clock_seconds();
    if (tick != last_memory) {
      unsigned long long available = memory_available();
      int pause = available < 128ULL * 1024 * 1024;
      trim_idle = available < 64ULL * 1024 * 1024;
      if (pause && !accepting_paused) {
        accepting_paused = 1;
        for (unsigned i = 0; i < nrings; i++) {
          Worker *w = &workers[i];
          if (w->accepting) {
            struct io_uring_sqe *s = sqe(w);
            io_uring_prep_cancel64(s, OP_ACCEPT, IORING_ASYNC_CANCEL_ALL);
            s->user_data = OP_CANCEL;
          }
        }
      } else if (!pause && accepting_paused) {
        accepting_paused = 0;
        for (unsigned i = 0; i < nrings; i++) {
          workers[i].full =
              workers[i].used + workers[i].accepting == file_slots;
          accept_arm(&workers[i]);
        }
      }
      last_memory = tick;
    }
    /* Incremental sweeping avoids a large pause at high connection counts. */
    if (tick != last_scan || scan_index || trim_idle) {
      Worker *w = &workers[scan_ring];
      unsigned end = scan_index + 2048;
      if (end > file_slots)
        end = file_slots;
      for (unsigned i = scan_index; i < end; i++) {
        Conn *c = &w->connections[i];
        if (c->active &&
            (tick - c->last_activity > (c->input_n || c->output ? 30u : 120u) ||
             (trim_idle && !c->input_n && !c->output &&
              tick - c->last_activity > 2)))
          close_connection(w, c);
      }
      scan_index = end;
      if (end == file_slots) {
        scan_index = 0;
        scan_ring = (scan_ring + 1) % nrings;
      }
      last_scan = tick;
    }
  }
  if (pending)
    flush();
  app_close();
  close(listener);
  for (unsigned i = 0; i < nrings; i++) {
    Worker *w = &workers[i];
    io_uring_queue_exit(&w->ring);
    for (unsigned j = 0; j < file_slots; j++) {
      release(w->connections[j].input);
      release(w->connections[j].output);
    }
    free(w->connections);
    munmap(w->buffers, (size_t)NBUFS * BUFSIZE);
  }
  for (unsigned i = 0; i < 4; i++) {
    Block *b = free_blocks[i];
    while (b) {
      Block *next = b->next;
      free(b);
      b = next;
    }
  }
  return 0;
}
