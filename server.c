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
#include "sha1.h"
#include "task.h"
#include "user_manager.h"

struct options {
    int random_seed;
    char* adj_file;
    char* animal_file;
    char* log_file;
};

static struct options default_options = {0, "adjectives", "animals", "task_log.txt"};

struct task_info {
    char block[MAX_BLOCK_LEN];
    uint32_t difficulty_mask;
    uint64_t nonce;
    uint64_t sequence_num;
    time_t start_time;
} current_task;

struct client_info {
    char *username;
    time_t heartbeat_timestamp;
    time_t request_timestamp;
};

static pthread_mutex_t lock;
static volatile sig_atomic_t running = 1;

uint32_t generate_mask(unsigned int zeros)
{
    if (zeros <= 0) {
        return 0xFFFFFFFF;
    }

    if (zeros >= 32) {
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
    uint8_t leading_zeros = __builtin_clz(current_task.difficulty_mask);
    if (current_task.start_time == 0) {
        leading_zeros = 1 + rand() % 25;
        current_task.difficulty_mask = generate_mask(leading_zeros);
    } else {
        double diff = difftime(now, current_task.start_time);
        LOG("Time to find solution = %f\n", diff);
        if (diff < 600.0) { // 10 min?
            current_task.difficulty_mask =
                increase_difficulty_mask(current_task.difficulty_mask);
        } else {
            current_task.difficulty_mask =
                decrease_difficulty_mask(current_task.difficulty_mask);
        }
        LOG("Difficulty change: %u -> %u\n",
            leading_zeros, __builtin_clz(current_task.difficulty_mask));
    }

    task_generate(current_task.block);
    current_task.start_time = now;
    current_task.sequence_num = current_task.sequence_num + 1;
    LOG("Generated new block [%lu]: %s\n",
        current_task.sequence_num, current_task.block);
    char mask_buf[33];
    sprint_binary32(current_task.difficulty_mask, mask_buf);
    LOG("Difficulty mask: %s (%u leading zeros)\n",
        mask_buf, __builtin_clz(current_task.difficulty_mask));
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

bool validate_heartbeat(struct client_info *u)
{
    return (difftime(time(NULL), u->heartbeat_timestamp) >= 10);
}

void handle_heartbeat(int fd, CoinMsg__Heartbeat *hb, struct client_info *user)
{
    LOG("[HEARTBEAT] User: %s\n", user->username);

    if (validate_heartbeat(user) == false) {
        LOG("%s", "[HEARTBEAT] User verification failed, sending empty response\n");

        send_task_reply(fd, "", 0, 0);
        return;
    }

    user->heartbeat_timestamp = time(NULL);

    CoinMsg__HeartbeatReply reply = COIN_MSG__HEARTBEAT_REPLY__INIT; 
    reply.sequence_num = current_task.sequence_num; 
    CoinMsg__Envelope envelope = COIN_MSG__ENVELOPE__INIT;
    envelope.heartbeat_reply = &reply;
    envelope.body_case = COIN_MSG__ENVELOPE__BODY_HEARTBEAT_REPLY;

    LOG("[HEARTBEAT] Sent heartbeat reply to %s: seq=%lu\n", user->username, current_task.sequence_num);
    write_envelope(fd, &envelope);
}

void handle_request_task(int fd, CoinMsg__TaskRequest *req, struct client_info *user)
{
    LOG("[TASK REQUEST] User: %s\n", user->username);

    if (difftime(time(NULL), user->request_timestamp) < 10) {
        // User has requested a task too soon, must wait 10 seconds
        send_task_reply(fd, "", 0, 0);
        return;
    }

    user->request_timestamp = time(NULL);
    send_task_reply(
        fd,
        current_task.block,
        current_task.difficulty_mask,
        current_task.sequence_num);
}

bool verify_solution(struct CoinMsg__VerificationRequest *solution)
{
    uint8_t digest[SHA1_HASH_SIZE];
    const char *check_format = "%s%lu";
    ssize_t buf_sz = snprintf(NULL, 0, check_format, current_task.block, solution->nonce);
    char *buf = malloc(buf_sz + 1);
    if (buf == NULL){
        perror("malloc failed");
        return false;
    }

    snprintf(buf, buf_sz + 1, check_format, current_task.block, solution->nonce);
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
    return (hash_front & current_task.difficulty_mask) == hash_front;
}

void handle_verification(
    int fd, CoinMsg__VerificationRequest *solution, struct client_info *user)
{
    LOG("[SOLUTION SUBMITTED] User: %s, block: %s, difficulty: %u, nonce: %lu\n",
        user->username,
        solution->block,
        solution->difficulty_mask,
        solution->nonce);

    /* We could directly verify the solution, but let's make sure it's the same
     * sequence number, block, and difficulty first: */
    if (current_task.sequence_num != solution->sequence_num) {
        send_verification_reply(fd, false, "Sequence number mismatch");
        return;
    }

    if (strcmp(current_task.block, solution->block) != 0)
    {
        send_verification_reply(
            fd, false, "Block does not match current block on server");
        return;
    }

    if (current_task.difficulty_mask !=  solution->difficulty_mask) {
        send_verification_reply(
            fd, false,
            "Difficulty does not match current difficulty on server");
        return;
    }

    pthread_mutex_lock(&lock); // lock before verification so that it is only executed by one thread at a time
    bool solution_ok = verify_solution(solution);

    LOG("[SOLUTION by %s %s!]\n", user->username, solution_ok ? "ACCEPTED" : "REJECTED");

    if (solution_ok) {
        // Update the user's request timestamp so they can request a new task
        // immediately after receiving the notification
        user->request_timestamp = 0;

        task_log_add(solution, user->username);
        generate_new_task();
        LOG("Generated new block: %s\n", current_task.block);
    }

    pthread_mutex_unlock(&lock); // unlock after verification

    send_verification_reply(fd, solution_ok, "Verified SHA-1 hash");
}

struct client_info *handle_registration(int fd, CoinMsg__RegistrationRequest *req)
{
    LOG("[REGISTRATION] User: %s\n", req->username);
    struct client_info *new_user = NULL;

    bool success = user_register(req->username);
    if (success == true) {
        new_user = calloc(1, sizeof(struct client_info));
        if (new_user == NULL) {
            LOG("%s", "Failed to allocate memory for user\n");
            send_registration_reply(fd, false);
            return NULL;
        }
        new_user->username = strdup(req->username);
        if (new_user->username == NULL) {
            LOG("%s", "strdup failed for username \n");
            free(new_user);
            send_registration_reply(fd, false);
            return NULL;
        }
    } else {
        LOG("User already exists: %s\n", req->username);
    }

    send_registration_reply(fd, success);
    return new_user;
}

void *client_thread(void* client_fd) {
    int fd = (int) (long) client_fd;
    struct client_info *this_user;

    while (true) {

        CoinMsg__Envelope *envelope = recv_envelope(fd);
        if(envelope == NULL){
            break;
        }

        switch (envelope->body_case) {
            case COIN_MSG__ENVELOPE__BODY_REGISTRATION_REQUEST:
                this_user = handle_registration(fd, envelope->registration_request);
                if (this_user == NULL) {
                    LOG("%s", "ERROR: Registration failed, closing client... \n");
                    break;
                }
                break;
            case COIN_MSG__ENVELOPE__BODY_TASK_REQUEST:
                if (!this_user) break;
                handle_request_task(fd, envelope->task_request, this_user);
                break;
            case COIN_MSG__ENVELOPE__BODY_VERIFICATION_REQUEST:
                if (!this_user) break;
                handle_verification(fd, envelope->verification_request, this_user);
                break;
            case COIN_MSG__ENVELOPE__BODY_HEARTBEAT:
                if (!this_user) break;
                handle_heartbeat(fd, envelope->heartbeat, this_user);
                break;

            default:
                LOG("ERROR: unknown message type: %d\n", envelope->body_case);
        }
        coin_msg__envelope__free_unpacked(envelope, NULL);
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


void* task_reset_thread(void* arg) {
    while(true) {
        sleep(60); 

        pthread_mutex_lock(&lock);
        time_t now = time(NULL);
        double diff = difftime(now, current_task.start_time);

        if (diff > 24 * 60 * 60) {
            generate_new_task();
            char ts[32];
            strftime(ts, sizeof ts, "%Y-%m-%d %H:%M:%S", localtime(&now));
            LOG("[RESET]: 24 Hours Elapsed - Generating New Task at %s\n", ts);
        }
        pthread_mutex_unlock(&lock);
    }
    return NULL;
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

    // create reset thread that will generate a new task if no solution has been
    // found in 24 hours
    pthread_t reset_thread;
    if (pthread_create(&reset_thread, NULL, task_reset_thread,NULL) != 0) {
        perror("pthread_create reset_thread");
        exit_code = 1;
        goto cleanup;
    }
    pthread_detach(reset_thread);

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

    if (socket_fd >= 0) {
        close(socket_fd);
    }

    task_log_close();
    task_destroy();

    user_manager_destroy();

    pthread_mutex_destroy(&lock);

    LOGP("Shutdown complete.\n");
    return exit_code;
}

