#include "task.h"

#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "coin-messages.pb-c.h"
#include "logger.h"

static size_t ani_idx = 0;
static size_t adj_idx = 0;

static FILE *log_file;

void fisher_yates(char *arr[], size_t sz);

size_t read_file(char filename[], char ***array);

char **animals;
char **adjectives;

static size_t adj_sz = 0; 
static size_t ani_sz = 0;

/**
 * Seeds the random number generator and then sets up task generation data
 * structures by shuffling task components.
 */
void task_init(char* adjective_file, char* animal_file)
{   
    ani_sz = read_file(animal_file, &animals);
    adj_sz = read_file(adjective_file, &adjectives);
    
    LOG("Initializing task generator. %zu animals, %zu adjectives (%zu x %zu = %zu)\n", ani_sz, adj_sz, ani_sz, adj_sz, adj_sz * ani_sz);
    assert(ani_sz != 0 && adj_sz != 0);

    size_t max_ani_len = 0;
    for (int i = 0; i < ani_sz; ++i)
    {
        size_t len = strlen(animals[i]);
        if (len > max_ani_len) {
            max_ani_len = len;
        }
    }
    LOG("Longest animal length: %zu\n", max_ani_len);

    size_t max_adj_len = 0;
    for (int i = 0; i < adj_sz; ++i)
    {
        size_t len = strlen(adjectives[i]);
        if (len > max_adj_len) {
            max_adj_len = len;
        }
    }
    LOG("Longest adjective length: %zu\n", max_adj_len);

    size_t longest_task_len = max_ani_len + max_adj_len + 1;
    assert(longest_task_len < MAX_BLOCK_LEN);
    
    LOGP("Shuffling animals.\n");
    fisher_yates(animals, ani_sz);

    LOGP("Shuffling adjectives.\n");
    fisher_yates(adjectives, adj_sz);

    LOGP("Task generator ready.\n");
}

void task_generate(char buf[MAX_BLOCK_LEN])
{
    sprintf(buf, "%s %s", adjectives[adj_idx++], animals[ani_idx++]);
    
    // roll over animals / adjectives on overflow
    if (adj_idx == adj_sz) {
        adj_idx = 0;
    }
    
    if (ani_idx == ani_sz) {
        ani_idx = 0;
    }
}

void task_log_open(char* file_name) {
    //Try to open the log file (create it if it doesn't already exist)
    log_file = fopen(file_name, "a+");
    if (log_file == NULL) {
        fprintf(stderr, "Error opening task log file\n");
    }
}

void task_log_add(CoinMsg__VerificationRequest *solution, char *username) {
    fprintf(
        log_file, 
        "%s\t%u\t%lu\t%s\t%ld\n", 
                solution->block, 
                solution->difficulty_mask, 
                solution->nonce, 
                username,
                time(NULL));

    //we fflush the file to ensure the write is on the disk after each update
    fflush(log_file);
}

void task_log_close(void)
{
    fclose(log_file);
}

void fisher_yates(char *arr[], size_t sz)
{
    for (int i = sz - 1; i > 0; i--) {
        int r = rand() % (i + 1);
        char *temp = arr[r];
        arr[r] = arr[i];
        arr[i] = temp;
    }
}

void destroy_array(char ***array, size_t size){
    if(array == NULL){
        return;
    }
    for(size_t i = 0; i < size; i++){
        free(array[i]);
        array[i] = NULL;
    }
    free(array);
}

size_t read_file(char filename[], char ***array){
    FILE *file = fopen(filename, "r");
    if ( file == NULL ){
        perror("fopen for file");
        return 0;
    }

    /* Determine the number of lines in the file */
    char buf[MAX_BLOCK_LEN] = { 0 };
    int i = 0;
    while (fgets(buf, sizeof(buf), file) != NULL) {
        i++;
    }
    *array = malloc(i * sizeof(char *));

    /* Read the contents */
    fseek(file, 0L, SEEK_SET);
    i = 0;
    while (fgets(buf, sizeof(buf), file) != NULL) {
        strtok(buf, "\r\n");
        
        (*array)[i] = strdup(buf);
        i++;
    }
    fclose(file);
    return i;
}

/*
* Prevents memory leaks, freeing everything
*/
void task_destroy() {
    // Free each index first
    for (int i = 0; i < ani_sz; i++) {
        free(animals[i]);
    }
    // Then free the whole array afterwards
    free(animals);

    // Same procedures
    for (int i = 0; i < adj_sz; i++) {
        free(adjectives[i]);
    }
    free(adjectives);
}
