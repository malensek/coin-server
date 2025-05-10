#include "common.h"
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>      // for htonl()
#include <protobuf-c/protobuf-c.h>
#include "coin.pb-c.h"
#include <stdbool.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>


int read_len(int fd, void *buf, size_t length)
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

int write_len(const int fd, const void *buf, size_t length)
{
  size_t total = 0;
  while (total < length) {
    ssize_t write_sz = write(fd, (char *)buf + total, length - total);
    if (write_sz == -1) {
        if (errno == EINTR) {
            // if we get interrupted then we should try reading again
            continue;
        }
      // read error
      perror("write");
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

int read_msg(int fd, union msg_wrapper *old)
{
      /* Step A: read the length */
      uint64_t len64;
      if (read_len(fd, &len64, sizeof(len64)) <= 0) return -1;
      size_t payload_len = (size_t)len64 - sizeof(len64);
  
      /* Step B: read the serialized Envelope */
      uint8_t *buf = malloc(payload_len);
      if (!buf) return -1;
      if (read_len(fd, buf, payload_len) <= 0) { free(buf); return -1; }
  
      /* Step C: unpack */
      Coin__Envelope *env = coin__envelope__unpack(NULL, payload_len, buf);
      free(buf);
      if (!env) return -1;
  
      /* Step D: copy fields back into your old union */
      switch (env->body_case) {
        case COIN__ENVELOPE__BODY_REQUEST_TASK:
          old->header.msg_type = MSG_REQUEST_TASK;
          strncpy(old->request_task.username,
                  env->request_task->username, MAX_USER_LEN);
          break;
  
        case COIN__ENVELOPE__BODY_TASK:
          old->header.msg_type            = MSG_TASK;
          strncpy(old->task.block,
                  env->task->block, MAX_DATA_LEN);
          old->task.difficulty_mask = env->task->difficulty_mask;
          old->task.sequence_num    = env->task->sequence_num;
          break;
  
        case COIN__ENVELOPE__BODY_SOLUTION:
          old->header.msg_type            = MSG_SOLUTION;
          strncpy(old->solution.username,
                  env->solution->username, MAX_USER_LEN);
          strncpy(old->solution.block,
                  env->solution->block, MAX_DATA_LEN);
          old->solution.difficulty_mask = env->solution->difficulty_mask;
          old->solution.nonce           = env->solution->nonce;
          old->solution.sequence_num    = env->solution->sequence_num;
          break;
  
        case COIN__ENVELOPE__BODY_VERIFICATION:
          old->header.msg_type             = MSG_VERIFICATION;
          old->verification.ok             = env->verification->ok;
          strncpy(old->verification.error_description,
                  env->verification->error_description, sizeof(old->verification.error_description));
          break;
  
        case COIN__ENVELOPE__BODY_HEARTBEAT:
          old->header.msg_type         = MSG_HEARTBEAT;
          strncpy(old->heartbeat.username,
                  env->heartbeat->username, MAX_USER_LEN);
          break;
  
        case COIN__ENVELOPE__BODY_HEARTBEAT_REPLY:
          old->header.msg_type               = MSG_HEARTBEAT_REPLY;
          old->heartbeat_reply.sequence_num  = env->heartbeat_reply->sequence_num;
          break;
  
        default:
          coin__envelope__free_unpacked(env, NULL);
          return -1;
      }
  
      coin__envelope__free_unpacked(env, NULL);
      old->header.msg_len = msg_size(old->header.msg_type);
      return sizeof(old->header.msg_len) + old->header.msg_len;
}

int write_msg(int fd, const union msg_wrapper *old)
{
  Coin__Envelope env = COIN__ENVELOPE__INIT;
    switch (old->header.msg_type) {
      case MSG_REQUEST_TASK: {
        Coin__RequestTask rt = COIN__REQUEST_TASK__INIT;
        rt.username = (char*)old->request_task.username;
        env.body_case       = COIN__ENVELOPE__BODY_REQUEST_TASK;
        env.request_task    = &rt;
        break;
      }
      case MSG_TASK: {
        Coin__Task tk = COIN__TASK__INIT;
        tk.block           = (char*)old->task.block;
        tk.difficulty_mask = old->task.difficulty_mask;
        tk.sequence_num    = old->task.sequence_num;
        env.body_case      = COIN__ENVELOPE__BODY_TASK;
        env.task           = &tk;
        break;
      }
      case MSG_SOLUTION: {
        Coin__Solution sol = COIN__SOLUTION__INIT;
        sol.username        = (char*)old->solution.username;
        sol.block           = (char*)old->solution.block;
        sol.difficulty_mask = old->solution.difficulty_mask;
        sol.nonce           = old->solution.nonce;
        sol.sequence_num    = old->solution.sequence_num;
        env.body_case       = COIN__ENVELOPE__BODY_SOLUTION;
        env.solution        = &sol;
        break;
      }
      case MSG_VERIFICATION: {
        Coin__Verification vf = COIN__VERIFICATION__INIT;
        vf.ok                = old->verification.ok;
        vf.error_description = (char*)old->verification.error_description;
        env.body_case        = COIN__ENVELOPE__BODY_VERIFICATION;
        env.verification     = &vf;
        break;
      }
      case MSG_HEARTBEAT: {
        Coin__Heartbeat hb = COIN__HEARTBEAT__INIT;
        hb.username       = (char*)old->heartbeat.username;
        env.body_case     = COIN__ENVELOPE__BODY_HEARTBEAT;
        env.heartbeat     = &hb;
        break;
      }
      case MSG_HEARTBEAT_REPLY: {
        Coin__HeartbeatReply hr = COIN__HEARTBEAT_REPLY__INIT;
        hr.sequence_num         = old->heartbeat_reply.sequence_num;
        env.body_case           = COIN__ENVELOPE__BODY_HEARTBEAT_REPLY;
        env.heartbeat_reply     = &hr;
        break;
      }
      default:
        return -1;
    }

    /* Step B: serialize it */
    size_t packed = coin__envelope__get_packed_size(&env);
    uint8_t *buf = malloc(packed);
    if (!buf) return -1;
    coin__envelope__pack(&env, buf);

    /* Step C: write length + data */
    uint64_t len64 = packed + sizeof(len64);
    if (write_len(fd, &len64, sizeof(len64)) < 0) { free(buf); return -1; }
    if (write_len(fd, buf, packed)     < 0) { free(buf); return -1; }
    free(buf);

    return sizeof(len64) + packed;
}

union msg_wrapper create_msg(enum MSG_TYPES type)
{
  union msg_wrapper wrapper = { 0 };
  wrapper.header.msg_type = type;
  wrapper.header.msg_len = msg_size(type);
  return wrapper;
}

// 