#include "server.h"

#include <arpa/inet.h>
#include <bits/getopt_core.h>
#include <dirent.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h> 
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>

#include "common.h"
#include "logger.h"
#include "task.h"
#include "sha1.h"

static union msg_wrapper current_task_wrapper;
struct msg_task *current_task = &current_task_wrapper.task;
static time_t task_start_time = 0;

static pthread_mutex_t lock;

struct options {
    int random_seed;
    char* adj_file;
    char* animal_file;
    char* log_file;
};

static struct options default_options = {0, "adjectives", "animals", "task_log.txt"};

struct user {
    char username[MAX_USER_LEN];
    time_t heartbeat_timestamp;
    time_t request_timestamp;
    struct user *next;
};

struct user *user_list = NULL;

uint32_t generate_mask(int zeros)
{
    if (zeros == 32) {
        return 0;
    }

    return 0xFFFFFFFF >> zeros;
}

uint32_t increase_difficulty_mask(uint32_t mask)
{
    if (mask == 0x01) {
        return 0;
    }
    
    return (mask >> 1);
}

uint32_t decrease_difficulty_mask(uint32_t mask)
{
    return (mask << 1) | 0x01;
}


void sprint_binary32(uint32_t num, char buf[33]) {
    int i, j;
    for (i = 31, j = 0; i >= 0; --i, j++) {
        uint32_t position = (unsigned int) 1 << i;
        buf[j] = ((num & position) == position) ? '1' : '0';
    }
    buf[32] = '\0';
}

void generate_new_task() {
    time_t now = time(NULL);
    uint8_t leading_zeros = __builtin_clz(current_task->difficulty_mask);
    if (task_start_time == 0) {
      leading_zeros = 1 + rand() % 25;
      current_task->difficulty_mask = generate_mask(leading_zeros);
    } else {
      double diff = difftime(now, task_start_time);
      LOG("Time to find solution = %f\n", diff);
      if (diff < 600.0) { // 10 min?
        current_task->difficulty_mask =
            increase_difficulty_mask(current_task->difficulty_mask);
      } else {
        current_task->difficulty_mask =
            decrease_difficulty_mask(current_task->difficulty_mask);
      }
      LOG("Difficulty change: %u -> %u\n", leading_zeros, __builtin_clz(current_task->difficulty_mask));
    }

    task_generate(current_task->block);
    task_start_time = now;
    current_task->sequence_num = current_task->sequence_num + 1;
    LOG("Generated new block [%lu]: %s\n", current_task->sequence_num, current_task->block);
    char mask_buf[33];
    sprint_binary32(current_task->difficulty_mask, mask_buf);
    LOG("Difficulty mask: %s (%u leading zeros)\n", mask_buf, __builtin_clz(current_task->difficulty_mask));
}

void print_usage(char *prog_name)
{
    printf("Usage: %s port [-s seed] [-a adjective_file] [-n animal_file] [-l log_file]" , prog_name);
    printf("\n");
    printf("Options:\n"
"    * -s    Specify the seed number\n"
"    * -a    Specify the adjective file to be used\n"
"    * -n    Specify the animal file to be used\n"
"    * -l    Specify the log file to be used\n");
    printf("\n");
}

struct user *find_user(char *username)
{
    struct user *curr_user = user_list;
    while (curr_user != NULL) {
      if (strcmp(curr_user->username, username) == 0) {
        return curr_user;
      }
      curr_user = curr_user->next;
    }
    return NULL;
    
}

struct user *add_user(char *username)
{
    struct user *u = calloc(1, sizeof(struct user));
    strncpy(u->username, username, MAX_USER_LEN - 1);
    u->heartbeat_timestamp = 0;
    u->next = user_list;
    user_list = u;
    return u;
}

bool validate_heartbeat(struct user *u)
{
    return (difftime(time(NULL), u->heartbeat_timestamp) >= 10);
}

void handle_heartbeat(int fd, struct msg_heartbeat *hb)
{
    LOG("[HEARTBEAT] User: %s\n", hb->username);
    union msg_wrapper wrapper = create_msg(MSG_HEARTBEAT_REPLY);

    struct user *user = find_user(hb->username);
    if (user == NULL || validate_heartbeat(user) == false) {
        wrapper.heartbeat_reply.sequence_num = 0;
        write_msg(fd, &wrapper);
        return;
    }

    user->heartbeat_timestamp = time(NULL);

    wrapper.heartbeat_reply.sequence_num = current_task->sequence_num;
    write_msg(fd, &wrapper);
}

void handle_request_task(int fd, struct msg_request_task *req)
{
    //LOG("[TASK REQUEST] User: %s, block: %s, difficulty: %u\n", req->username, current_block, current_difficulty_mask);
    LOG("[TASK REQUEST] User: %s\n", req->username);
    struct user *user = find_user(req->username);
    if (user == NULL) {
        LOG("Adding new user account: %s\n", req->username);
        user = add_user(req->username);
    }

    if (difftime(time(NULL), user->request_timestamp) < 10) {
        // User has requested a task too soon, must wait 10 seconds
        union msg_wrapper wrapper = create_msg(MSG_TASK);
        wrapper.task.sequence_num = 0;
        write_msg(fd, &wrapper);
        return;
    }

    user->request_timestamp = time(NULL);
    write_msg(fd, &current_task_wrapper);
}

bool verify_solution(struct msg_solution *solution)
{
    uint8_t digest[SHA1_HASH_SIZE];
    const char *check_format = "%s%lu";
    ssize_t buf_sz = snprintf(NULL, 0, check_format, current_task->block, solution->nonce);
    char *buf = malloc(buf_sz + 1);
    if(buf == NULL){
        perror("malloc");
        return false;
    }

    snprintf(buf, buf_sz + 1, check_format, current_task->block, solution->nonce);
    sha1sum(digest, (uint8_t *) buf, buf_sz);
    char hash_string[SHA1_STR_SIZE];
    sha1tostring(hash_string, digest);
    LOG("SHA1sum: '%s' => '%s'\n", buf, hash_string);
    free(buf);

    /* Get the first 32 bits of the hash */
    uint32_t hash_front = 0;
    hash_front |= digest[0] << 24;
    hash_front |= digest[1] << 16;
    hash_front |= digest[2] << 8;
    hash_front |= digest[3];

    /* Check to see if we've found a solution to our block */
    return (hash_front & current_task->difficulty_mask) == hash_front;
}

void handle_solution(int fd, struct msg_solution *solution)
{
    LOG("[SOLUTION SUBMITTED] User: %s, block: %s, difficulty: %u, NONCE: %lu\n", solution->username, solution->block, solution->difficulty_mask, solution->nonce);
    
    union msg_wrapper wrapper = create_msg(MSG_VERIFICATION);
    struct msg_verification *verification = &wrapper.verification;
    verification->ok = false; // assume the solution is not valid by default

    /* We could directly verify the solution, but let's make sure it's the same
     * sequence number, block, and difficulty first: */
    if (current_task->sequence_num != solution->sequence_num) {
        strcpy(verification->error_description, "Sequence number mismatch");
        write_msg(fd, &wrapper);
        return;
    }

    if (strcmp(current_task->block, solution->block) != 0)
    {
        strcpy(verification->error_description, "Block does not match current block on server");
        write_msg(fd, &wrapper);
        return;
    }
    
    if (current_task->difficulty_mask !=  solution->difficulty_mask) {
        strcpy(verification->error_description, "Difficulty does not match current difficulty on server");
        write_msg(fd, &wrapper);
        return;
    }

    struct user *u = find_user(solution->username);
    if (u == NULL) {
        strcpy(verification->error_description, "Unknown user");
        write_msg(fd, &wrapper);
        return;
    }

    pthread_mutex_lock(&lock); // lock before verification so that it is only executed by one thread at a time
    verification->ok = verify_solution(solution);

    LOG("[SOLUTION by %s %s!]\n", solution->username, verification->ok ? "ACCEPTED" : "REJECTED");

    if (verification->ok) {
        // Update the user's request timestamp so they can request a new task
        // immediately after receiving the notification
        u->request_timestamp = 0;

        task_log_add(solution);
        generate_new_task();
        LOG("Generated new block: %s\n", current_task->block);
    }
    
    pthread_mutex_unlock(&lock); // unlock after verification

    strcpy(verification->error_description, "Verified SHA-1 hash");
    write_msg(fd, &wrapper);
}

void *client_thread(void* client_fd) {
    int fd = (int) (long) client_fd;
    bool should_exit = false; // Flag to see if we should exit the while loop
    while (true) {

      union msg_wrapper msg;
       ssize_t bytes_read = read_msg(fd, &msg);
       if(bytes_read == -1){
            perror("read_msg");
	    should_exit = true; // Break out of the loop
            break;
       }
       else if (bytes_read == 0) {
           LOGP("Disconnecting client\n");
           should_exit = true; // Break out of the loop
           break;
       }
       if (difftime(time(NULL), task_start_time) > 24 * 60 * 60) {
            generate_new_task();
            LOG("Task unsolved for 24 hours. Generated new block: %s\n", current_task->block);
        }

        switch (msg.header.msg_type) {
            case MSG_REQUEST_TASK: handle_request_task(fd, (struct msg_request_task *) &msg.request_task);
                                   break;
            case MSG_SOLUTION: handle_solution(fd, (struct msg_solution *) &msg.solution);
                               break;
            case MSG_HEARTBEAT: handle_heartbeat(fd, (struct msg_heartbeat *) &msg.heartbeat);
                                break;
            default:
                LOG("ERROR: unknown message type: %d\n", msg.header.msg_type);
        }
    }
    // Once we break we close and return null
    close(fd);
    return NULL;
}

/*
* Handling SIGINT -> Tells the server to stop listening to connections and terminate ellegantly
*/
void sigint_handler(int signo) {
    printf("SIGINT received. Goodbye...\n\n");
    task_log_close();
    task_destroy();
    pthread_mutex_destroy(&lock);
    exit(0);
}

int main(int argc, char *argv[]) {
    // Handling signals
    signal(SIGINT, sigint_handler);

    if (pthread_mutex_init(&lock, NULL) != 0) {
        printf("\n mutex init failed\n");
        return 1;
    }

    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    struct options opts;
    opts = default_options;

    int port = atoi(argv[1]);
    int c;
    opterr = 0;
    while ((c = getopt(argc, argv, "s:a:n:l:")) != -1) {
        switch (c) {
        char *end;
            case 's':
                opts.random_seed = (int) strtol(optarg, &end, 10);
                LOG("seed is %d\n", opts.random_seed);
                if (end == optarg) {
                    return 1;
                }
                break;
            case 'a':
                opts.adj_file = optarg;
                LOG("adj file is %s\n", opts.adj_file);
                break;
            case 'n':
                opts.animal_file = optarg;
                LOG("animal file is %s\n", opts.animal_file);
                break;
            case 'l':
                opts.log_file = optarg;
                LOG("log file is %s\n", opts.log_file);
                break;
        }
    }
    
    LOG("Starting coin-server version %.1f...\n", VERSION);
    LOG("%s", "(c) 2023 CS 521 Students\n");

    if (opts.random_seed == 0) {
        opts.random_seed = time(NULL);
    }
    LOG("Random seed: %d\n", opts.random_seed);
    srand(opts.random_seed);
    
   
    task_init(opts.adj_file, opts.animal_file);
    current_task_wrapper = create_msg(MSG_TASK);
    generate_new_task();
    task_log_open(opts.log_file);

    // create a socket
    int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd == -1) {
        perror("socket");
        return 1;
    }

    // bind to the port specified above
    struct sockaddr_in addr = { 0 };
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    if (bind(socket_fd, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
        perror("bind");
        return 1;
    }

    // start listening for clients to connect
    if (listen(socket_fd, 10) == -1) {
        perror("listen");
        return 1;
    }

    LOG("Listening on port %d\n", port);

    while (true) {
        /* Outer loop: this keeps accepting connection */
        struct sockaddr_in client_addr = { 0 };
        socklen_t slen = sizeof(client_addr);

	// accept client connection
        int client_fd = accept(
                socket_fd,
                (struct sockaddr *) &client_addr,
                &slen);

        if (client_fd == -1) {
            perror("accept");
            return 1;
        }


	// find out their info (host name, port)
        char remote_host[INET_ADDRSTRLEN];
        inet_ntop(
                client_addr.sin_family,
                (void *) &((&client_addr)->sin_addr),
                remote_host,
                sizeof(remote_host));
        LOG("Accepted connection from %s:%d\n", remote_host, client_addr.sin_port);

        pthread_t thread;
        pthread_create(&thread, NULL, client_thread, (void *) (long) client_fd);
        pthread_detach(thread);
    }
    //Closing log_file before we exit the server.
    // Add finishing commands to sigint handler function
    return 0; 
}
