#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "hashtable.h"
#include "request.h"

#define FALSE 0
#define TRUE 1

/* TABLE ENTRY STRUCT */
struct table_entry {
  char *word;
  unsigned long word_id;
  struct file_data *data;
};

/* HASH TABLE STRUCT */
struct table {
	/* you can define this struct to have whatever fields you want. */
    long max_size;
    long size;
    struct table_entry **entries;
};

/* TABLE ENTRY FUNCTIONS */
void print_t_entry              (struct table_entry *t_entry);
struct table_entry *entry_init  (char *word, unsigned long key, struct file_data *data);

/* HASH TABLE FUNCTIONS */
unsigned long hash_djb2         (unsigned char *str);
unsigned long find_new_key      (struct table *table, char *word);
unsigned long find_word_key     (struct table *table, char *word);
int is_available                (struct table *table, char *word);
struct file_data *look_up       (struct table *table, char *word);
void print_table                (struct table *table);
int delete_entry                (struct table *table, char *word);

/* GENERAL FUNCTIONS */
void print_words                (char *char_arr, long length);

struct table *
table_init(long size)
{
    struct table *table = (struct table *)malloc(sizeof(struct table));
    assert(table);
    table->entries = malloc(size*sizeof(struct table_entry *));
    assert(table->entries);

    int i;
    for (i=0; i<size; i++) 
        table->entries[i] = NULL;

    table->max_size = size;
    table->size = 0;
    
    return table;
}

void
table_output(struct table *table)
{
    print_table(table);
    
}

void
table_destroy(struct table *table)
{
    long i=0;
    while (i < table->max_size)
    {
        if (table->entries[i]!=NULL) {
            free(table->entries[i]);
            table->entries[i] = NULL;
        }
        i++;
    }
    free(table->entries);
    free(table);
    
    return;
}

/* TABLE HELPER FUNCTIONS */
void print_table (struct table *table) {
    long row = 0;
    struct table_entry **entries = table->entries;
    printf("SIZE: %ld, MAX_SIZE: %ld \n", table->size, table->max_size);
    while (row < table->max_size) {
        if (entries[row] != NULL) 
            print_t_entry(entries[row]);
        row++;
    }
}
void
print_data (struct table *table, char *word) {
    unsigned long key = find_word_key(table, word);
    print_t_entry(table->entries[key]);
}
int
insert_entry(struct table *table, char *input_string, struct file_data *data) {
    // unsigned long key = hash%table->max_size;
    if (is_available(table, input_string)==FALSE)
        return FALSE;

    unsigned long key = find_new_key(table, input_string);
    table->entries[key] = entry_init(input_string, key, data);
    table->size++;

    return TRUE;
}
unsigned long
hash_djb2 (unsigned char *str)
{
//    unsigned long hash = 5381;
    unsigned long hash = 98317;
    int c;

    while ((c = *str++))
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */

    return hash;
}
unsigned long 
find_new_key(struct table *table, char *word) {
    // error check
    assert(table->max_size!=table->size);

    unsigned long hash = hash_djb2((unsigned char *)word);
    unsigned long key = hash%table->max_size;
    while (table->entries[key]!=NULL) {
        key = (key+1)%table->max_size;
    }
    return key;
}
int 
is_available (struct table *table, char *word) {
    // error check
    assert(table->max_size!=table->size);

    unsigned long hash = hash_djb2((unsigned char *)word);
    unsigned long key = hash%table->max_size;
    while (table->entries[key]!=NULL) {
        if (strcmp(table->entries[key]->word, word)==0) {
            // TEST
            printf ("not available !!!\n");
            return FALSE;
        }
        key = (key+1)%table->max_size;   
    }
    return TRUE;
}
unsigned long 
find_word_key (struct table *table, char *word) {
    unsigned long hash = hash_djb2((unsigned char *)word);
    unsigned long key = hash%table->max_size;

    // error check
    unsigned long first_key = key;
    assert(table->entries[key] != NULL);

    while (strcmp(table->entries[key]->word, word)!=0) {
        key = (key+1)%table->max_size;

        // error check: avoid full cycle and going 
        // back to same key (forever loop)
        assert(key!=first_key);
    }
    return key;
}
struct file_data *
look_up (struct table *table, char *word) {
    if (is_available(table, word))
        //available means word is not in table
        return NULL;

    unsigned long key = find_word_key(table, word);
    // TEST
    print_t_entry(table->entries[key]);
    return table->entries[key]->data;
}
int 
delete_entry (struct table *table, char *word) {
    unsigned long key = find_word_key(table, word);
    free(table->entries[key]);
    table->entries[key] = NULL;
    table->size--;
    return TRUE;
}
long
get_t_size (struct table *table) {
    return table->size;
}
long 
get_t_maxsize (struct table *table) {
    return table->max_size;
}

/* TABLE ENTRY FUNCTIONS */
void 
print_t_entry (struct table_entry *t_entry)
{
    printf ("[i:%lu | key:%s | data:(name:%s,buff:%s,size:%d)] \n", 
            t_entry->word_id,
            t_entry->word,
            t_entry->data->file_name,
            t_entry->data->file_buf,
            t_entry->data->file_size);
}
struct table_entry *
entry_init(char *word, unsigned long key, struct file_data *data) {
    struct table_entry *t_entry = malloc(sizeof(struct table_entry));
    t_entry->word_id = key;
    t_entry->word = word;
    t_entry->data = data;   
    return t_entry;
}