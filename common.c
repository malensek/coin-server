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

size_t msg_size(enum MSG_TYPES type)
{
        switch (type) {
            case MSG_REQUEST_TASK: return sizeof(struct msg_request_task);
            case MSG_TASK: return sizeof(struct msg_task);
            case MSG_SOLUTION: return sizeof(struct msg_solution);
            case MSG_VERIFICATION: return sizeof(struct msg_verification);
            case MSG_HEARTBEAT: return sizeof(struct msg_heartbeat);
            case MSG_HEARTBEAT_REPLY: return sizeof(struct msg_heartbeat_reply);
            default: assert(false && "Message size not known!");
        }
}

int read_msg(int fd, union msg_wrapper *msg)
{
  ssize_t header_sz = read_len(fd, msg, sizeof(struct msg_header));
  if (header_sz <= 0) {
    return header_sz;
  }



  void *payload_ptr = (char *)msg + sizeof(struct msg_header);
  ssize_t payload_sz = read_len(fd, payload_ptr, msg->header.msg_len - sizeof(struct msg_header));
  if (payload_sz <= 0) {
    return payload_sz;
  }
  
  size_t total_size = header_sz + payload_sz;
  assert((total_size < sizeof(union msg_wrapper) + sizeof(struct msg_header)) && "Cannot read message larger than wrapper union!");

  return total_size;
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

int write_msg(int fd, const union msg_wrapper *msg)
{
  return write_len(fd, msg, msg->header.msg_len);
}

union msg_wrapper create_msg(enum MSG_TYPES type)
{
  union msg_wrapper wrapper = { 0 };
  wrapper.header.msg_type = type;
  wrapper.header.msg_len = msg_size(type);
  return wrapper;
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
