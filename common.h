#ifndef _COMMON_H_
#define _COMMON_H_

#include <stdbool.h>
#include <stdio.h>
#include <inttypes.h>

#include "task.h"
#include "coin-messages.pb-c.h"

#ifndef DEBUG_ON
#define DEBUG_ON 1
#endif

#define MAX_USER_LEN 24

/**
 * Function: read_len
 * Purpose:  reads from an input stream, retrying until a specific number of
 *           bytes has been read. This ensures complete message delivery.
 *
 * Args:
 *  * fd     - the file descriptor to read from
 *  * buf    - pointer to buffer to store data
 *  * length - size of the incoming message. If less than 'length' bytes are
 *             received, we'll keep retrying the read() operation.
 */
ssize_t read_len(int fd, void *buf, size_t length);

ssize_t write_len(const int fd, const void *buf, size_t length);

CoinMsg__Envelope *recv_envelope(int fd);

void send_registration_reply(int fd, bool ok);
void send_task_reply(int fd, char *block, uint32_t difficulty_mask, uint64_t sequence_num);
void send_verification_reply(int fd, bool ok, char *diagnostic);
ssize_t write_envelope(int fd, const CoinMsg__Envelope *envelope);
#endif
