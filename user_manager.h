#ifndef USER_MANAGER_H
#define USER_MANAGER_H

#include <time.h>
#include <stdbool.h>


struct user {
    char username[MAX_USER_LEN];
    time_t heartbeat_timestamp;
    time_t request_timestamp;
};

void user_manager_init();

void user_manager_destroy();

struct user *add_user(char *username);

struct user *find_user(char *username);

bool validate_heartbeat(struct user *u);

void user_update_heartbeat(struct user *u);

void user_reset_request_timer(struct user *u);

bool user_can_request_task(struct user *u);

#endif
