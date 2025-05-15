#ifndef TASK_H
#define TASK_H

#include "coin-messages.pb-c.h"

#define MAX_BLOCK_LEN 128

void task_init(char* adjective_file, char* animal_file);
void task_generate(char buf[MAX_BLOCK_LEN]);
void task_destroy();
void task_log_open(char *file);
void task_log_add(CoinMsg__VerificationRequest *solution, char *username);
void task_log_close(void);

#endif
