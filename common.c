#include "common.h"
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>

#include "coin-messages.pb-c.h"
#include <stdbool.h>
#include <assert.h>
#include <stdlib.h>
#include "logger.h"

ssize_t read_len(int fd, void *buf, size_t length)
{
  size_t total = 0;
  while (total < length) {
    ssize_t read_sz = read(fd, (char *)buf + total, length - total);
    if (read_sz == -1) {
        if (errno == EINTR) {
            // if we get interrupted then we should try reading again
            continue;
        }
      // read error
      perror("read");
      return -1;
    } else if (read_sz == 0) {
      // eof
      return 0;
    }

    total += read_sz;
  }
  if (DEBUG_ON) {
  for (int i = 0; i < length; ++i) {
    fprintf(stderr, "%02X ", ((char *) buf)[i]);
  }
  fprintf(stderr, "\n");
  }
  return total;
}

ssize_t write_len(const int fd, const void *buf, size_t length)
{
  size_t total = 0;
  while (total < length) {
    ssize_t write_sz = write(fd, (char *)buf + total, length - total);
    if (write_sz == -1) {
        if (errno == EINTR) {
            // if we get interrupted then we should try reading again
            continue;
        }
      // write error
      perror("write_len");
      return -1;
    }

    total += write_sz;
  }

if(DEBUG_ON) {
  for (int i = 0; i < length; ++i) {
    fprintf(stderr, "%02X ", ((char *) buf)[i]);
  }
  fprintf(stderr, "\n");
}

  return total;
}

CoinMsg__Envelope *recv_envelope(int fd)
{
    uint32_t msg_size;
    ssize_t prefix_bytes = read_len(fd, &msg_size, sizeof(uint32_t));
    if (prefix_bytes == 0 || prefix_bytes == -1) {
      perror("read_len");
      return NULL;
    }

  msg_size = ntohl(msg_size);
    LOG("Receiving message wrapper, size: %u\n", msg_size);
    void *buf = malloc(msg_size);
    ssize_t wrapper_bytes = read_len(fd, buf, msg_size);
    if (wrapper_bytes == -1 || wrapper_bytes == 0) {
      perror("read_len");
        free(buf);
        return NULL;
    }

    CoinMsg__Envelope *envelope
        = coin_msg__envelope__unpack(NULL, msg_size, buf);
    free(buf);
    return envelope;
}

ssize_t write_envelope(int fd, const CoinMsg__Envelope *envelope)
{
  size_t resp_sz = coin_msg__envelope__get_packed_size(envelope);
  void *buf = malloc(resp_sz);
  coin_msg__envelope__pack(envelope, buf);

  uint32_t net_prefix = htonl(resp_sz);
  write_len(fd, &net_prefix, sizeof(uint32_t));
  ssize_t result = write_len(fd, buf, resp_sz);
  free(buf);
  return result;
}

void send_registration_reply(int fd, bool ok)
{
  CoinMsg__RegistrationReply reply = COIN_MSG__REGISTRATION_REPLY__INIT;
  reply.ok = ok;

  CoinMsg__Envelope envelope = COIN_MSG__ENVELOPE__INIT;
  envelope.registration_reply = &reply;
  envelope.body_case = COIN_MSG__ENVELOPE__BODY_REGISTRATION_REPLY;

  write_envelope(fd, &envelope);
}

void send_task_reply(
  int fd, char *block, uint32_t difficulty_mask, uint64_t sequence_num)
{
  CoinMsg__TaskReply reply = COIN_MSG__TASK_REPLY__INIT;
  reply.block = block;
  reply.difficulty_mask = difficulty_mask;
  reply.sequence_num = sequence_num;

  CoinMsg__Envelope envelope = COIN_MSG__ENVELOPE__INIT;
  envelope.task_reply = &reply;
  envelope.body_case = COIN_MSG__ENVELOPE__BODY_TASK_REPLY;

  write_envelope(fd, &envelope);
}

void send_verification_reply(int fd, bool ok, char *diagnostic)
{
  CoinMsg__VerificationReply reply = COIN_MSG__VERIFICATION_REPLY__INIT;
  reply.ok = ok;
  reply.diagnostic = diagnostic;

  CoinMsg__Envelope envelope = COIN_MSG__ENVELOPE__INIT;
  envelope.verification_reply = &reply;
  envelope.body_case = COIN_MSG__ENVELOPE__BODY_VERIFICATION_REPLY;

  write_envelope(fd, &envelope);
}
