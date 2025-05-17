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
#include <errno.h>

#include "coin-messages.pb-c.h"
#include "common.h"
#include "logger.h"
#include "task.h"
#include "sha1.h"
#include "user_manager.h"

static union msg_wrapper current_task_wrapper;
struct msg_task *current_task = &current_task_wrapper.task;
static time_t task_start_time = 0;

static pthread_mutex_t lock;

static volatile sig_atomic_t running = 1;

struct options {
    int random_seed;
    char* adj_file;
    char* animal_file;
    char* log_file;
};

static struct options default_options = {0, "adjectives", "animals", "task_log.txt"};


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
    return find_user(username);
}

struct user *add_user(char *username)
{
    return user_add(username);
}

bool validate_heartbeat(struct user *u)
{
    return user_is_heartbeat_valid(u);
}

void pb_handle_heartbeat(int fd, CoinMsg__Heartbeat *hb, struct user *user)
{
    LOG("[HEARTBEAT] User: %s\n", user->username);
    union msg_wrapper wrapper = create_msg(MSG_HEARTBEAT_REPLY);

    if (validate_heartbeat(user) == false) {
        wrapper.heartbeat_reply.sequence_num = 0;
        write_msg(fd, &wrapper);
        return;
    }

    user->heartbeat_timestamp = time(NULL);

    wrapper.heartbeat_reply.sequence_num = current_task->sequence_num;
    write_msg(fd, &wrapper);
}

void handle_request_task(int fd, CoinMsg__TaskRequest *req, struct user *user)
{
    LOG("[TASK REQUEST] User: %s\n", user->username);

    if (!user_can_request_task(user)) {
        // User has requested a task too soon, must wait 10 seconds
        send_task_reply(fd, "", 0, 0);
        return;
    }

    user->request_timestamp = time(NULL);
    send_task_reply(
        fd,
        current_task_wrapper.task.block,
        current_task_wrapper.task.difficulty_mask,
        current_task_wrapper.task.sequence_num);
}

bool verify_solution(struct CoinMsg__VerificationRequest *solution)
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

void handle_verification(int fd, CoinMsg__VerificationRequest *solution, struct user *user)
{
    LOG("[SOLUTION SUBMITTED] User: %s, block: %s, difficulty: %u, NONCE: %lu\n", user->username, solution->block, solution->difficulty_mask, solution->nonce);
    
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

    struct user *u = find_user(user->username);
    if (u == NULL) {
        strcpy(verification->error_description, "Unknown user");
        write_msg(fd, &wrapper);
        return;
    }

    pthread_mutex_lock(&lock); // lock before verification so that it is only executed by one thread at a time
    verification->ok = verify_solution(solution);

    LOG("[SOLUTION by %s %s!]\n", user->username, verification->ok ? "ACCEPTED" : "REJECTED");

    if (verification->ok) {
        // Update the user's request timestamp so they can request a new task
        // immediately after receiving the notification
        u->request_timestamp = 0;

        task_log_add(solution, user->username);
        generate_new_task();
        LOG("Generated new block: %s\n", current_task->block);
    }
    
    pthread_mutex_unlock(&lock); // unlock after verification

    send_verification_reply(fd, verification->ok, "Verified SHA-1 hash");
}

struct user *handle_registration(int fd, CoinMsg__RegistrationRequest *req)
{
    LOG("[REGISTRATION] User: %s\n", req->username);

    struct user *new_user = add_user(req->username);
    bool success = new_user != NULL;

    if (success == false) {
        LOG("User already exists: %s\n", req->username);
    }

    send_registration_reply(fd, success);
    return new_user;
}

void *client_thread(void* client_fd) {
    int fd = (int) (long) client_fd;
    struct user *this_user = NULL;

    while (true) {

        CoinMsg__Envelope *envelope = recv_envelope(fd);
        if(envelope == NULL){
            break;
        }
       if (difftime(time(NULL), task_start_time) > 24 * 60 * 60) {
            generate_new_task();
            LOG("Task unsolved for 24 hours. Generated new block: %s\n", current_task->block);
        }

        switch (envelope->body_case) {
            case COIN_MSG__ENVELOPE__BODY_REGISTRATION_REQUEST:
                this_user = handle_registration(fd, envelope->registration_request);
                break;
            case COIN_MSG__ENVELOPE__BODY_TASK_REQUEST:
                handle_request_task(fd, envelope->task_request, this_user);
                break;
            case COIN_MSG__ENVELOPE__BODY_VERIFICATION_REQUEST:
                handle_verification(fd, envelope->verification_request, this_user);
                break;

            default:
                LOG("ERROR: unknown message type: %d\n", envelope->body_case);
        }
    }
    // Once we break we close and return null
    close(fd);
    return NULL;
}

/**
 * Handles signals to shut the main thread down, stop listening for connections,
 * and clean up.
 */
void shutdown_handler(int signo) {
    running = 0;
}

int main(int argc, char *argv[]) {
    int exit_code = 0;
    
    // Handle clean shutdown on SIGINT / SIGTERM
    struct sigaction sa = { 0 };
    sa.sa_handler = shutdown_handler;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

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
    LOG("%s", "(c) 2025 CS 521 Students\n");

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
        exit_code = 1;
        goto cleanup;
    }

    // allow immediate reuse of the address if in TIME_WAIT
    int opt = 1;
    if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt(SO_REUSEADDR)");
    }

    // bind to the port specified above
    struct sockaddr_in addr = { 0 };
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    if (bind(socket_fd, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
        perror("bind");
        exit_code = 1;
        goto cleanup;
    }

    // start listening for clients to connect
    if (listen(socket_fd, 10) == -1) {
        perror("listen");
        exit_code = 1;
        goto cleanup;
    }

    LOG("Listening on port %d\n", port);

    while (running) {
        struct sockaddr_in client_addr = { 0 };
        socklen_t slen = sizeof(client_addr);

        // accept client connection
        int client_fd = accept(
                socket_fd,
                (struct sockaddr *) &client_addr,
                &slen);

        if (client_fd == -1) {
            if (errno == EINTR && running == false) {
                // Interrupted by signal, time to shut down
                break;
            } else {
                perror("accept");
                continue;
            }
        }

	// Get client info (host name, port)
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

cleanup:
    LOGP("Shutting down...\n");

    close(socket_fd);

    task_log_close();
    task_destroy();

    pthread_mutex_destroy(&lock);

    LOGP("Shutdown complete.\n");
    return exit_code;
}