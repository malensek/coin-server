#include "user_manager.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

struct user_node {
    struct user user_data;
    struct user_node *next;
};

static struct user_node *user_list = NULL;
static pthread_mutex_t user_mutex = PTHREAD_MUTEX_INITIALIZER;

void user_manager_init() {
    pthread_mutex_lock(&user_mutex);
    user_list = NULL;
    pthread_mutex_unlock(&user_mutex);
}

void user_manager_destroy() {
    pthread_mutex_lock(&user_mutex);
    struct user_node *curr = user_list;
    while (curr) {
        struct user_node *tmp = curr;
        curr = curr->next;
        free(tmp);
    }
    user_list = NULL;
    pthread_mutex_unlock(&user_mutex);
    pthread_mutex_destroy(&user_mutex);
}

struct user *find_user(char *username) {
    pthread_mutex_lock(&user_mutex);
    struct user_node *curr = user_list;
    while (curr) {
        if (strcmp(curr->user_data.username, username) == 0) {
            struct user *result = &curr->user_data;
            pthread_mutex_unlock(&user_mutex);
            return result;
        }
        curr = curr->next;
    }
    pthread_mutex_unlock(&user_mutex);
    return NULL;
}

struct user *add_user(char *username) {
    pthread_mutex_lock(&user_mutex);

    struct user_node *curr = user_list;
    while (curr) {
        if (strcmp(curr->user_data.username, username) == 0) {
            pthread_mutex_unlock(&user_mutex);
            return NULL;  
        }
        curr = curr->next;
    }

    struct user_node *new_node = calloc(1, sizeof(struct user_node));
    if (!new_node) {
        pthread_mutex_unlock(&user_mutex);
        return NULL;
    }

    strncpy(new_node->user_data.username, username, MAX_USER_LEN - 1);
    new_node->user_data.heartbeat_timestamp = 0;
    new_node->user_data.request_timestamp = 0;
    new_node->next = user_list;
    user_list = new_node;

    struct user *result = &new_node->user_data;
    pthread_mutex_unlock(&user_mutex);
    return result;
}

bool validate_heartbeat(struct user *u) {
    return difftime(time(NULL), u->heartbeat_timestamp) >= 10;
}

void user_update_heartbeat(struct user *u) {
    u->heartbeat_timestamp = time(NULL);
}

void user_reset_request_timer(struct user *u) {
    u->request_timestamp = 0;
}

bool user_can_request_task(struct user *u) {
    return difftime(time(NULL), u->request_timestamp) >= 10;
}
