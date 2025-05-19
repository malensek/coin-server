#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "user_manager.h"

struct user_node {
    char *username;
    struct user_node *next;
};

static struct user_node *user_list = NULL;
static pthread_mutex_t user_mutex;

void delete_node(struct user_node *node)
{
    free(node->username); // strdup'd during initialization
    free(node);
}

void user_manager_destroy() {
    pthread_mutex_lock(&user_mutex);
    struct user_node *curr = user_list;
    while (curr) {
        struct user_node *tmp = curr;
        curr = curr->next;
        delete_node(tmp);
    }
    user_list = NULL;
    pthread_mutex_unlock(&user_mutex);
    pthread_mutex_destroy(&user_mutex);
}

bool user_remove(char *username) {
    pthread_mutex_lock(&user_mutex);

    struct user_node *curr = user_list;
    struct user_node *prev = NULL;
    while (curr) {
        if (strcmp(curr->username, username) == 0) {
            if (prev == NULL) {
                user_list = curr->next;
                delete_node(curr);
                pthread_mutex_unlock(&user_mutex);
                return true;
            } else {
                prev->next = curr->next;
                delete_node(curr);
                pthread_mutex_unlock(&user_mutex);
                return true;
            }
        }
        prev = curr;
        curr = curr->next;
    }

    pthread_mutex_unlock(&user_mutex);
    return false;
}

bool user_register(char *username) {
    pthread_mutex_lock(&user_mutex);

    struct user_node *curr = user_list;
    while (curr != NULL) {
        if (strcmp(curr->username, username) == 0) {
            pthread_mutex_unlock(&user_mutex);
            return false;  
        }
        curr = curr->next;
    }

    struct user_node *new_node = calloc(1, sizeof(struct user_node));
    if (new_node == NULL) {
        pthread_mutex_unlock(&user_mutex);
        return NULL;
    }

    new_node->username = strdup(username);
    new_node->next = user_list;
    user_list = new_node;

    pthread_mutex_unlock(&user_mutex);
    return true;
}

