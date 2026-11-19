/* K02 transport probe, not the MAccConc GUI protocol. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/vm_sockets.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static int fail(const char *stage) {
  int saved = errno;
  fprintf(stderr, "%s: %s\n", stage, strerror(saved));
  printf("{\"passed\":false,\"stage\":\"%s\",\"errno\":%d}\n", stage, saved);
  return 1;
}

static int transfer(int fd, void *data, size_t size, int sending) {
  unsigned char *bytes = data;
  while (size) {
    ssize_t n = sending ? send(fd, bytes, size, MSG_NOSIGNAL) : recv(fd, bytes, size, 0);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) { if (n == 0) errno = ECONNRESET; return -1; }
    bytes += n; size -= (size_t)n;
  }
  return 0;
}

static unsigned int number(const char *arg) {
  char *end;
  errno = 0;
  unsigned long value = strtoul(arg, &end, 0);
  if (errno || !arg[0] || *end || value > UINT_MAX) {
    fprintf(stderr, "invalid unsigned argument: %s\n", arg); exit(2);
  }
  return (unsigned int)value;
}

static void print_hex(const unsigned char *bytes, size_t count) {
  for (size_t i = 0; i < count; ++i) printf("%02x", bytes[i]);
}

int main(int argc, char **argv) {
  if (argc > 4) {
    fprintf(stderr, "usage: %s [host-cid [port [timeout-seconds]]]\n", argv[0]); return 2;
  }
  unsigned int cid = argc > 1 ? number(argv[1]) : VMADDR_CID_HOST;
  unsigned int port = argc > 2 ? number(argv[2]) : 0x4b434f56;
  unsigned int timeout = argc > 3 ? number(argv[3]) : 30;
  if (!timeout || timeout > 300) { errno = EINVAL; return fail("timeout-range"); }
  unsigned char request[40] = {'K','0','2','V','S','O','C','K'};
  size_t generated = 0;
  while (generated < 32) {
    ssize_t n = getrandom(request + 8 + generated, 32 - generated, 0);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) return fail("getrandom");
    generated += (size_t)n;
  }
  int fd = socket(AF_VSOCK, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
  if (fd < 0) return fail("socket-vsock");
  struct sockaddr_vm host = {.svm_family = AF_VSOCK, .svm_port = port, .svm_cid = cid};
  if (connect(fd, (struct sockaddr *)&host, sizeof(host))) {
    if (errno != EINPROGRESS) { int saved = errno; close(fd); errno = saved; return fail("connect-vsock"); }
    struct pollfd wait = {.fd = fd, .events = POLLOUT};
    int count;
    do { count = poll(&wait, 1, (int)timeout * 1000); } while (count < 0 && errno == EINTR);
    if (count <= 0) { int saved = count == 0 ? ETIMEDOUT : errno; close(fd); errno = saved; return fail("connect-wait"); }
    int error = 0; socklen_t length = sizeof(error);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) || error) {
      int saved = error ? error : errno; close(fd); errno = saved; return fail("connect-result");
    }
  }
  if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) & ~O_NONBLOCK) < 0) {
    int saved = errno; close(fd); errno = saved; return fail("blocking-mode");
  }
  struct timeval limit = {.tv_sec = timeout};
  if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &limit, sizeof(limit)) ||
      setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &limit, sizeof(limit))) {
    int saved = errno; close(fd); errno = saved; return fail("socket-timeout");
  }
  struct sockaddr_vm peer = {0}; socklen_t peer_len = sizeof(peer);
  if (getpeername(fd, (struct sockaddr *)&peer, &peer_len)) {
    int saved = errno; close(fd); errno = saved; return fail("peer-address");
  }
  if (peer.svm_family != AF_VSOCK || peer.svm_cid != cid || peer.svm_port != port) {
    close(fd); errno = EPROTO; return fail("peer-address-mismatch");
  }
  unsigned char response[64];
  if (transfer(fd, request, sizeof(request), 1) || transfer(fd, response, sizeof(response), 0)) {
    int saved = errno; close(fd); errno = saved; return fail("nonce-exchange");
  }
  if (memcmp(response, request + 8, 32)) { close(fd); errno = EPROTO; return fail("guest-nonce-mismatch"); }
  if (transfer(fd, response + 32, 32, 1)) { int saved = errno; close(fd); errno = saved; return fail("host-nonce-return"); }
  unsigned char acknowledged;
  if (transfer(fd, &acknowledged, 1, 0)) {
    int saved = errno; close(fd); errno = saved; return fail("host-acknowledgement");
  }
  if (acknowledged != 1) { close(fd); errno = EPROTO; return fail("host-acknowledgement"); }
  struct sockaddr_vm local = {0}; socklen_t local_len = sizeof(local);
  if (getsockname(fd, (struct sockaddr *)&local, &local_len)) { int saved = errno; close(fd); errno = saved; return fail("socket-bind-address"); }
  /* Linux autobind retains VMADDR_CID_ANY in local_addr. This is the bind
   * address, not a query for the transport's actual local CID; the server
   * records that CID from its accepted peer address. */
  printf("{\"passed\":true,\"scope\":\"vsock-transport-only\",\"host_cid\":%u,\"socket_bind_cid\":%u,\"observed_peer_cid\":%u,\"port\":%u,\"guest_nonce\":\"", cid, local.svm_cid, peer.svm_cid, port);
  print_hex(request + 8, 32); printf("\",\"host_nonce\":\""); print_hex(response + 32, 32); puts("\"}");
  close(fd); return 0;
}
