#include "request.h"
#include "server_thread.h"
#include "common.h"

#define MAX_BUFF 10
#define FALSE 0
#define TRUE 1
#define ERR_FULL -1

/* cache constants */
#define GOOD 1
#define BAD 0
#define T_INSERT_REDUNDANT -2
#define T_FULL_AND_INSERT_REDUNDANT -3
#define ERR_EVICT_SPOIL -4

/********************** data structs definition ****************************/

struct server {
	int nr_threads;
	int max_requests;
	int max_cache_size;
	/* add any other parameters you need */
};

struct monitor_t {
	struct server *sv;
	char *buff;
	int in, 
		out, 
		buff_size;
	pthread_mutex_t lock;
	pthread_cond_t empty, 
					full;
};

/* queue struct */
struct queue_t {
    struct node *head;
    struct node *tail;
    int size;
};

/* node struct */
struct node {
    // unsigned long key;
    char *name;
    struct node *next;
    struct node *prev;
};

/* pthread pool */
struct pthread_pool_t {
	pthread_t *pthreads;
	int *ptids;
	int n_threads;
};

/* FILE STRUCT */
struct file {
	char *file_name;
	char *file_buf;
	int file_size; 
    struct node *file_node;
};

/* TABLE ENTRY STRUCT */
struct table_entry {
  // char *word;
  int sending;
  struct file *file;
  unsigned long word_id;
};

/* HASH TABLE STRUCT */
struct table {
    long max_size;
    long size;
    struct table_entry **entries;
};

/********************** data structs definition ****************************/

/*********************** data structs methods ******************************/
/* monitor functions */
struct monitor_t *monitor_init 		(struct server *sv, int n_threads);
void buff_write(					int msg);
int buff_read ();
/* monitor helper functions */
int buff_full ();
int buff_empty ();
void print_buff ();

/* pthread pool functions */
void Pthread_pool_init 				(struct pthread_pool_t *ptpool, int n_threads);
void Pthread_pool_destroy 			(struct pthread_pool_t *ptpool);
/* wrapper functions */
void Pthread_create 				(pthread_t *t, 
									const pthread_attr_t *attr, 
									void *(*start_routine)(void *), 
								    void *arg);

/* QUEUE api functions */
struct queue_t *queue_init ();
struct node *pop 					(struct queue_t *queue);
void push							(struct queue_t *queue, struct node *node);
void queue_destroy 					(struct queue_t *queue);
void print_queue					(struct queue_t *queue);

/* LRU api functions */
struct node *flash_pop				(struct queue_t *queue, struct node *node);
void update_LRU 					(struct queue_t *queue, struct node *node);

/* NODE api functions */
struct node *node_init				(char *name);
// long unsigned get_node_key			(struct node *node);
char *get_node_name					(struct node *node);

/* TABLE api functions */
struct table *table_init			(long size);
void table_output					(struct table *table);
void table_destroy					(struct table *table);
void print_table					(struct table *table);
void print_word						(struct table *table, char *word);
void print_t_entry 					(struct table_entry *t_entry);
void print_t_entry_min 				(struct table_entry *t_entry);
char *word_look_up					(struct table *table, char *word);
struct table_entry *look_up 		(struct table *table, char *word);
int insert_entry					(struct table *table, struct file *file);
int delete_entry 					(struct table *table, char *word);
long get_t_size 					(struct table *table);
long get_t_maxsize 					(struct table *table);

/* FILE api functions */
struct file *file_init 				(char *file_name, char *file_buf, int file_size);
struct file *file_init_deep			(char *file_name, char *file_buf, int file_size);
char *get_file_name 				(struct file *file);
void set_file_name 					(struct file *file, char *file_name);
char *get_file_buf 					(struct file *file);
void set_file_buf 					(struct file *file, char *file_buf);
int get_file_size 					(struct file *file);
void set_file_size 					(struct file *file, int file_size);

/* file_data api functions */
void set_data_name					(struct file_data *data, char *data_name);
char *get_data_name					(struct file_data *data);
void set_data_buf					(struct file_data *data, char *data_buf);
char *get_data_buf					(struct file_data *data);
void set_data_size					(struct file_data *data, int data_size);
int get_data_size					(struct file_data *data);
struct file_data *set_data 			(struct file_data *data, struct file *file);
struct file_data *get_data 			(struct file *file);
struct file_data *cpy_lookup_sync 	(char *file_name);
int cpy_insert_sync 				(struct file_data *data);
/* TABLE_ENTRY api functions */
struct table_entry *entry_init 		(unsigned long key, struct file *file);
struct file *get_file 				(struct table_entry *t_entry);
void set_file 						(struct table_entry *t_entry, struct file *file);
unsigned long 
get_entry_wordid 					(struct table_entry *t_entry);
char *get_entry_word 				(struct table_entry *t_entry);
struct node *get_file_node 			(struct file *file);
void set_file_node 					(struct file *file, struct node *file_node);

/* HASHTABLE helper functions */
unsigned long hash_djb2         	(unsigned char *str);
unsigned long find_new_key      	(struct table *table, char *word);
unsigned long find_word_key     	(struct table *table, char *word);
int is_available                	(struct table *table, char *word);
int is_full                     	(struct table *table);
char *word_look_up              	(struct table *table, char *word);
struct table_entry *look_up     	(struct table *table, char *word);
void print_table                	(struct table *table);
void print_table_min                (struct table *table);

/* cache api functions */
int cache_insert 					(struct table *cache, struct file *file);
struct file *cache_lookup 			(struct table *cache, char *file_name);
int cache_evict 					(struct table *cache, int n);
int cache_insert_sync 				(struct table *cache, struct file *file);
struct file *cache_lookup_sync		(struct table *cache, char *file_name);
struct file_data *data_lookup_sync	(char *file_name);
int cache_evict_sync				(struct table *cache, int n);
void print_table_sync				(struct table *cache);

/* cache helper functions */
int cache_full 						(struct table *cache);
int cache_reach_maxdata 			(struct table *cache);

/* cache_entry helper functions */
void print_cache_entry 				(struct table_entry* t_entry);
void print_cache_entry_sync 		(struct table_entry* t_entry);

/* FILE helper functions */
void print_file 					(struct file *file);
/*********************** data structs methods ******************************/

/******************** global structs declaration ***************************/
struct pthread_pool_t *ptpool;
struct monitor_t *monitor;
struct table *cache;
struct queue_t *LRU;
pthread_mutex_t l; // cache lock
pthread_mutex_t sender_lock;
/******************** global structs declaration ***************************/


/* static functions */
static void do_server_request(struct server *sv, int connfd);

/* initialize file data */
static struct file_data *
file_data_init(void)
{
	struct file_data *data;

	data = Malloc(sizeof(struct file_data));
	data->file_name = NULL;
	data->file_buf = NULL;
	data->file_size = 0;
	return data;
}

/* free all file data */
// static void
// file_data_free(struct file_data *data)
// {
// 	free(data->file_name);
// 	free(data->file_buf);
// 	free(data);
// }

void *
dsr_stub (void *args) {
	while (1) {
		int connfd = buff_read();
		struct server *sv = monitor->sv;
		do_server_request(sv, connfd);
	}
}

static void
do_server_request(struct server *sv, int connfd) {
	int ret;
	struct request *rq;
	struct file_data *data;

	data = file_data_init();

	/* fills data->file_name with name of the file being requested */
	rq = request_init(connfd, data);
	if (!rq) {
		// file_data_free(data);
		return;
	}


	if (cache_lookup_sync(cache, data->file_name)==NULL) {
		// printf("request_readfile %s\n", data->file_name);
		ret = request_readfile(rq);
		if (!ret)
			goto out;		
	} else {
		// // deep copy file from cache
		// data = cpy_lookup_sync(data->file_name);
		// printf("cpy_lookup_sync %s\n", data->file_name);
		data = data_lookup_sync(data->file_name);
		// printf("data_lookup_sync(%s)\n", data->file_name);
		// request_set_data
		request_set_data(rq, data);
	}

	/* reads file, 
	 * fills data->file_buf with the file contents,
	 * data->file_size with file size. */
	// ret = request_readfile(rq);
	// if (!ret)
	// 	goto out;
	/* sends file to client */

	// memcpy(cpyfilename, data->file_name, str(data->file_name)+1);
	// printf("memcpy name: %s\n", cpyfilename);

	request_sendfile(rq);
	cache_insert_sync(cache, file_init(	data->file_name, 
										data->file_buf, 
										data->file_size));
out:
	request_destroy(rq);
	// file_data_free(data);
}

/* entry point functions */

struct server *
server_init(int nr_threads, 
			int max_requests, 
			int max_cache_size)
{
	struct server *sv;

	sv = Malloc(sizeof(struct server));
	sv->nr_threads = nr_threads;
	sv->max_requests = max_requests;
	sv->max_cache_size = max_cache_size;

	if (nr_threads > 0 || max_requests > 0 || max_cache_size > 0) {
		/* monitor is global */
		monitor = monitor_init(sv, nr_threads);
		/* cache is global */
		cache = table_init(5*max_cache_size);
		LRU = queue_init();
		pthread_mutex_init(&l, NULL);
		// pthread_mutex_init(&sender_lock, NULL);
		/* pthread_pool is global */
		ptpool = malloc(sizeof(struct pthread_pool_t));
		Pthread_pool_init(ptpool, nr_threads);
	}

	/* Lab 4: create queue of max_request size when max_requests > 0 */

	/* Lab 5: init server cache and limit its size to max_cache_size */

	/* Lab 4: create worker threads when nr_threads > 0 */

	return sv;
}

void
server_request(struct server *sv, int connfd)
{
	if (sv->nr_threads == 0) { /* no worker threads */
		do_server_request(sv, connfd);
	} else {
		/*  Save the relevant info in a buffer and have one of the
		 *  worker threads do the work. */
		buff_write(connfd);
	}
}

/* monitor functions */
struct monitor_t *
monitor_init (struct server *sv, int n_threads) {
	struct monitor_t *monitor = malloc(sizeof(struct monitor_t));
	monitor->sv = sv;
	monitor->buff_size = n_threads + 1;
	monitor->buff = malloc(sizeof(int)*monitor->buff_size);
	monitor->in = 0;
	monitor->out = 0;
	pthread_mutex_init(&monitor->lock, NULL);
	pthread_cond_init(&monitor->empty, NULL);
	pthread_cond_init(&monitor->full, NULL);
	assert(monitor);
	return monitor;
}
void
buff_write (int msg) {
	pthread_mutex_lock(&monitor->lock);
	while (buff_full()) {
		pthread_cond_wait(&monitor->full, &monitor->lock);
	}
	monitor->buff[monitor->in] = msg;
	if (buff_empty()) {
		pthread_cond_signal(&monitor->empty);
	}
	monitor->in = (monitor->in+1)%monitor->buff_size;
	// printf("WRITE by %lu: buff[in==%d,out==%d]: %s \n", 
	// 	pthread_self(), 
	// 	monitor->in, 
	// 	monitor->out, 
	// 	monitor->buff);
	// print_buff();
	pthread_mutex_unlock(&monitor->lock);
}
int
buff_read () {
	pthread_mutex_lock(&monitor->lock);
	while (buff_empty()) {
		pthread_cond_wait(&monitor->empty, &monitor->lock);
	}
	// printf("READ by %lu: buff[in==%d,out==%d]: %s \n", 
	// 	pthread_self(), 
	// 	monitor->in, 
	// 	monitor->out, 
	// 	monitor->buff);
	// print_buff();
	char msg = monitor->buff[monitor->out];
	if (buff_full()) {
		pthread_cond_signal(&monitor->full);
	}
	monitor->out =  (monitor->out+1)%monitor->buff_size;
	pthread_mutex_unlock(&monitor->lock);
	return msg;
}

/* pthreads helper functions */
void
Pthread_pool_init (struct pthread_pool_t *ptpool, int n_threads) {
	ptpool->pthreads = malloc(sizeof(pthread_t)*n_threads);
	ptpool->ptids = malloc(sizeof(int)*n_threads);
	ptpool->n_threads = n_threads;

	int i;
	for (i=0; i<n_threads; i++) {
		ptpool->ptids[i]=i+1;
		Pthread_create(&(ptpool->pthreads[i]), 
						NULL, 
						dsr_stub, 
						NULL);
	}
	return;
}

/* monitor helper functions */
int
buff_full () {return ((monitor->in - monitor->out + monitor->buff_size)%monitor->buff_size == monitor->buff_size - 1);}
int
buff_empty () {return (monitor->in == monitor->out);}
void
print_buff () {
	int buff_size = monitor->buff_size;
	int i;
	printf("[ ");
	for (i=0; i<buff_size; i++) {
		printf("%d, ", monitor->buff[i]);
	}
	printf(" ]\n");
}

/* wrapper functions */
void
Pthread_create(	pthread_t *t, 
				const pthread_attr_t *attr, 
	    		void *(*start_routine)(void *), 
	    		void *arg) 
{
    int rc = pthread_create(t, attr, start_routine, arg);
    assert(rc == 0);
}

/*
--------------------------HASHTABLE FUNCTIONS-------------------------------
*/

/* HASHTABLE api functions */
struct table *
table_init (long size)
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
table_output(struct table *table) {
    print_table(table);    
}
void
table_destroy(struct table *table) {
    long i=0;
    while (i < table->max_size)
    {
        if (table->entries[i]!=NULL) {
            free(table->entries[i]->file);
            free(table->entries[i]);
            table->entries[i] = NULL;
        }
        i++;
    }
    free(table->entries);
    free(table);
    
    return;
}

/* HASHTABLE helper functions */
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
void print_table_min (struct table *table) {
    long row = 0;
    struct table_entry **entries = table->entries;
    printf("SIZE: %ld, MAX_SIZE: %ld \n", table->size, table->max_size);
    while (row < table->max_size) {
        if (entries[row] != NULL) 
            print_t_entry_min(entries[row]);
        row++;
    }
}
void
print_word (struct table *table, char *word) {
    unsigned long key = find_word_key(table, word);
    print_t_entry(table->entries[key]);
}
int
insert_entry (struct table *table, struct file *file) {
	char *input_string = get_file_name(file);
    if (is_full(table)==TRUE)
        return ERR_FULL;
    if (is_available(table, input_string)==FALSE)
        return 0;

    unsigned long key = find_new_key(table, input_string);
    table->entries[key] = entry_init(key, file);
    table->size++;

    return 1;
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
    assert(table->size<=table->max_size);

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
    assert(table->size<=table->max_size);

    unsigned long hash = hash_djb2((unsigned char *)word);
    unsigned long key = hash%table->max_size;
    unsigned long first_key = key;
    while (table->entries[key]!=NULL) {
        // printf("is_available(table, \'%s\')\n", word);
        // printf("key==%lu\n", key);
        // if (strcmp(table->entries[key]->word, word)==0) {
    	if (strcmp(table->entries[key]->file->file_name, word)==0) {
            // printf ("%s not available !!!\n", word);
            return 0;
        }
        key = (key+1)%table->max_size; 
        if (key==first_key) 
            return TRUE;
    }
    return TRUE;
}
int
is_full (struct table *table) {
    return (table->size==table->max_size);
}
unsigned long 
find_word_key (struct table *table, char *word) {
    unsigned long hash = hash_djb2((unsigned char *)word);
    unsigned long key = hash%table->max_size;

    unsigned long first_key = key;
    do {
        if (table->entries[key]!=NULL)
            if (strcmp(table->entries[key]->file->file_name, word)==0)
                return key;
        key = (key+1)%table->max_size;
    } while (first_key!=key);
    // expected to find the word
    assert(0);
    return key;
}
char *
word_look_up (struct table *table, char *word) {
    if (is_available(table, word))
        //available means word is not in table
        return NULL;
    unsigned long key = find_word_key(table, word);
    return table->entries[key]->file->file_name;
}
struct table_entry *
look_up (struct table *table, char *word) {
    // printf("look_up(\'%s\')\n", word);
    // print_table(table);
    if (is_available(table, word))
        //available means word is not in table
        return NULL;

    unsigned long key = find_word_key(table, word);
    return table->entries[key];
}
int 
delete_entry (struct table *table, char *word) {
    printf("deleting table[\'%s\']...\n", word);
    unsigned long key = find_word_key(table, word);
    free(table->entries[key]->file);
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

/* table entry functions */
void 
print_t_entry (struct table_entry *t_entry)
{
    printf ("[i:%lu | data:(name:%s,buff:%s,size:%d)] \n", 
            t_entry->word_id,
            get_file_name(t_entry->file),
            get_file_buf(t_entry->file),
            get_file_size(t_entry->file));
}
void 
print_t_entry_min (struct table_entry *t_entry)
{
	int buff = GOOD;
	if (get_file_buf(t_entry->file)==NULL)
		buff = BAD;
    printf ("[i:%lu | data:(name:%s,buff:%d,size:%d)] \n", 
            t_entry->word_id,
            get_file_name(t_entry->file),
            buff,
            get_file_size(t_entry->file));
}
struct table_entry *
entry_init (unsigned long key, struct file *file) {
    struct table_entry *t_entry = malloc(sizeof(struct table_entry));
    t_entry->word_id = key;
    t_entry->sending = FALSE;
    t_entry->file = file;   
    return t_entry;
}

/*
--------------------------FILE api functions----------------------------------
*/
/* FILE api functions */
struct file *
file_init (char *file_name, char *file_buf, int file_size) {
    struct file *file = malloc(sizeof(struct file));
	// memcpy(file->file_name, file_name, strlen(file_name)+1);
 	//memcpy(file->file_buf, file_buf, strlen(file_buf)+1);
    file->file_name = file_name;
    file->file_buf = file_buf;
    file->file_size = file_size;
    return file;
}
struct file *
file_init_deep (char *file_name, char *file_buf, int file_size) {
    struct file *file = malloc(sizeof(struct file));
    // file->file_name = malloc(sizeof(char)*(strlen(file_name)+1));
    // file->file_buf = malloc(sizeof(char)*)
	memcpy(file->file_name, file_name, strlen(file_name)+1);
 	memcpy(file->file_buf, file_buf, strlen(file_buf)+1);
    // file->file_name = file_name;
    // file->file_buf = file_buf;
    file->file_size = file_size;
    return file;
}
char *
get_file_name (struct file *file) {
    return file->file_name;
}
void 
set_file_name (struct file *file, char *file_name) {
    file->file_name = file_name;
}
char *
get_file_buf (struct file *file) {
    return file->file_buf;
}
void 
set_file_buf (struct file *file, char *file_buf) {
    file->file_buf = memcpy(file->file_buf, file_buf, strlen(file_buf)+1);
}
int 
get_file_size (struct file *file) {
    return file->file_size;
}
void 
set_file_size (struct file *file, int file_size) {
    file->file_size = file_size;
}
/*
--------------------------TABLE_ENTRY api functions----------------------------------
*/
/* TABLE_ENTRY api functions */
struct file *
get_file (struct table_entry *t_entry) {
    return t_entry->file;
}
void 
set_file (struct table_entry *t_entry, struct file *file) {
    t_entry->file = file;
}
unsigned long 
get_entry_wordid (struct table_entry *t_entry) {
    return t_entry->word_id;
}
char *
get_entry_word (struct table_entry *t_entry) {
    return t_entry->file->file_name;
}
struct node *
get_file_node (struct file *file) {
    return file->file_node;
}
void
set_file_node (struct file *file, struct node *file_node) {
    file->file_node = file_node;
}

/*
--------------------------QUEUE api functions----------------------------------
*/
/* queue functions */
struct queue_t * 
queue_init () {
	struct queue_t *queue = malloc(sizeof(struct queue_t));
	queue->head = NULL;
	queue->tail = NULL;
	queue->size = 0;
	return queue;
}
struct node * 
pop (struct queue_t *queue) {
	// error check
	assert(queue);

	struct node *node = queue->head;
	if (node == NULL)
		return NULL;
	// no sibling
	if (node->next == NULL)
	{
		queue->head = NULL;
		queue->tail = NULL;
	}
	else
	{
		queue->head = node->next;
		queue->head->prev = NULL;
		node->next = NULL;
	}
	queue->size--;
	return node;
}
void 
push (struct queue_t *queue, struct node *node) {
	// error checks
	assert(queue);

	if (queue->head == NULL) {
		// check for first push to head
		queue->head = node;
		queue->tail = node;
		node->prev = NULL;
		node->next = NULL;
	} else {
		// else push to end of queue (tail)
		node->prev = queue->tail;
		queue->tail->next = node;
		node->next = NULL;
		queue->tail = node;
	}
	queue->size++;
	return;
}
void 
queue_destroy (struct queue_t *queue) {
	struct node *node = pop(queue);
	while (node!=NULL) {
		free(node);
		node = pop(queue);
	}
	free(queue);
	return;
}
void
print_queue (struct queue_t *queue) {
	struct node *node = queue->head;
	printf("Q[%d]:<", queue->size);
	while (node!=NULL) {
		printf("--%p %s--", 
					node,
					node->name);
		node = node->next;
	}
	printf(">\n");
	return;	
}

/* NODE api functions */
struct node *
node_init (char *name) {
	struct node *node = malloc(sizeof(struct node));
	node->name = name;
	node->next = NULL;
	node->prev = NULL;
	return node;
}
char *
get_node_name (struct node *node) {
	return node->name;
}
// long unsigned
// get_node_key (struct node *node) {
// 	return node->key;
// }

/* queue DEBUG functions */
struct node *
get_next (struct node *node) {
	return node->next;
}

/*
--------------------------LRU api functions----------------------------------
*/
/* 				!!!!!!!CAUTION!!!!!! 						*/
// before using flash_pop, assert that table connected with 
// LRU actually has a pointer to node that is about to pop
struct node *
flash_pop (struct queue_t *queue, struct node *node) {
	assert(node!=NULL);
	if (node->next==NULL && node->prev==NULL) {
		queue->tail = NULL;
		queue->head = NULL;
	} 
	else if (node->next==NULL) 
	{
		queue->tail = node->prev;
		node->prev->next = NULL;
		node->prev = NULL;
	} 
	else if (node->prev==NULL) 
	{
		queue->head = node->next;
		node->next->prev = NULL;
		node->next = NULL;
	} 
	else 
	{
		node->next->prev = node->prev;
		node->prev->next = node->next;
		node->next = NULL;
		node->prev = NULL;
	}
	queue->size--;
	return node;
}
void 
update_LRU (struct queue_t *queue, struct node *node) {
	node = flash_pop(queue, node);
	push(queue, node);
}

/*
--------------------------CACHE api functions----------------------------------
*/
/* cache api functions */
int
cache_insert (struct table *cache, struct file *file) {
	char *file_name = get_file_name(file);
	// if (cache_full(cache)) {
	if (cache_reach_maxdata(cache)) {
		// printf("%lu: cache is full, now chech whether cache has %s or not\n", pthread_self(), file_name);
		if (look_up(cache, file_name)!=NULL) 
		{
			// printf("%lu: cache oredy has %s (T_FULL_AND_INSERT_REDUNDANT)\n", pthread_self(), file_name);
			return T_FULL_AND_INSERT_REDUNDANT;
		} 
		else if (cache_evict(cache, 10)==ERR_EVICT_SPOIL) 
		{
			// printf("%lu: cache does not have %s (ERR_EVICT_SPOIL)\n", pthread_self(), file_name);
			return BAD;
		}
	} else {
		// printf("%lu: cache is not full, now whether it has %s or not\n", pthread_self(), file_name);
		if (look_up(cache, file_name)!=NULL) {
			// printf("cache oredy has %s (T_INSERT_REDUNDANT)\n", file_name);
			return T_INSERT_REDUNDANT;
		}
		// printf("%lu: cache does not have %s \n", pthread_self(), file_name);
	}
	// insert & push to LRU
	insert_entry(cache, file);
	struct table_entry *t_entry = look_up(cache, file_name);
	// struct file *file = file_init(file_name, i++);
	set_file(t_entry, file);
	struct node *file_node = node_init(file_name);
	set_file_node(file, file_node);
	push(LRU, file_node);

	return GOOD;
}
struct file *
cache_lookup (struct table *cache, char *file_name) {
	// at each lookup, update file_node in LRU
	if (look_up(cache, file_name)==NULL)
		return NULL;

	struct file *file = get_file(look_up(cache, file_name));
	struct node *file_node = get_file_node(file);

	// // TEST
	// if (get_next(file_node)==NULL) {
	// 	print_table(cache);
	// 	print_queue(LRU);
	// }
	update_LRU(LRU, file_node);
	return file;
}
int
cache_evict (struct table *cache, int n) {
	// printf("thread %lu evicting... \n", pthread_self());

	if (n>get_t_maxsize(cache))
		return ERR_EVICT_SPOIL;

	// print_table(cache);
	// printf("Q: ");
	// print_queue(LRU);
	// evict n entries (including respective nodes)
	int evicts = 0;
	while (evicts<n) {
		// printf("evicts==%d\n", evicts);
		struct node *lru_node = pop(LRU);
	// print_table(cache);
	// printf("Q: ");
	// print_queue(LRU);
		delete_entry(cache, get_node_name(lru_node));
		free(lru_node);
	// print_table(cache);
	// printf("Q: ");
	// print_queue(LRU);
		evicts++;
	}
	return GOOD;
}
int 
cache_insert_sync (struct table *cache, struct file *file) {
	// print_file(file);
	pthread_mutex_lock(&l);
	// struct file *file = file_init_deep(file__->file_name, 
	// 									file__->file_buf, 
	// 									file__->file_size);
	// printf("thread %lu cache_insert_sync %s\n", pthread_self(), get_file_name(file));
	// printf("cache_insert_sync %s \n", get_file_name(file));
	int ret = cache_insert(cache, file);
	// if (ret==T_INSERT_REDUNDANT)
		// printf("T_INSERT_REDUNDANT \n");
	print_table_min(cache);
	// print_queue(LRU);

	// if (ret==ERR_EVICT_SPOIL)
		// printf("ERR_EVICT_SPOIL\n");

	pthread_mutex_unlock(&l);
	return ret;
}
struct file *
cache_lookup_sync (struct table *cache, char *file_name) {
	pthread_mutex_lock(&l);
	// printf("thread %lu cache_lookup_sync %s\n", pthread_self(), file_name);
	struct file *ret = cache_lookup(cache, file_name);
	// print_file(ret);
	// print_queue(LRU);
	pthread_mutex_unlock(&l);
	return ret;
}
int 
cache_evict_sync (struct table *cache, int n) {
	pthread_mutex_lock(&l);
	int ret = cache_evict(cache, n);
	pthread_mutex_unlock(&l);	
	return ret;
}
void 
print_table_sync (struct table *cache) {
	pthread_mutex_lock(&l);
	print_table(cache);
	pthread_mutex_unlock(&l);
}

/* cache helper functions */
int 
cache_full (struct table *cache) {
	return (get_t_size(cache)==get_t_maxsize(cache));
}
int 
cache_reach_maxdata (struct table *cache) {
	return (get_t_size(cache)==(get_t_maxsize(cache)/2));
}

/* cache_entry helper functions */
void 
print_cache_entry (struct table_entry* t_entry) {
	printf("[ ");
	if (t_entry!=NULL) {
		printf("(%lu,%s) | name:%s ", 
							get_entry_wordid(t_entry), 
							get_entry_word(t_entry),
							get_file_name(get_file(t_entry)));
	}
	printf(" ] \n");
}
void 
print_cache_entry_sync (struct table_entry* t_entry) {
	pthread_mutex_lock(&l);
	printf("[ ");
	if (t_entry!=NULL) {
		printf("(%lu,%s) | name:%s ", 
							get_entry_wordid(t_entry), 
							get_entry_word(t_entry),
							get_file_name(get_file(t_entry)));
	}
	printf(" ] \n");
	pthread_mutex_unlock(&l);
}

/* file helper functions */
void 
print_file (struct file *file) {
	printf("F[ ");
	if (file!=NULL) {
		printf("%s : %s : %p", 
					get_file_name(file),
					get_file_buf(file),
					get_file_node(file));
	} else {
		printf("NULL");
	}
	printf(" ]F\n");
}

void
set_sending (struct file *file) {
	char *file_name = get_file_name(file);
	if (is_available(cache, file_name))
		return;
	long unsigned key = find_word_key(cache, file_name);
	cache->entries[key]->sending = TRUE;
}
void set_sending_sync (struct file *file) {
	pthread_mutex_lock(&sender_lock);
	set_sending(file);
	pthread_mutex_unlock(&sender_lock);
}
void 
unset_sending (struct file *file) {
	char *file_name = get_file_name(file);
	if (is_available(cache, file_name))
		return;
	long unsigned key = find_word_key(cache, file_name);
	cache->entries[key]->sending = FALSE;	
}
void
unset_sending_sync (struct file *file) {
	pthread_mutex_lock(&sender_lock);
	unset_sending(file);
	pthread_mutex_unlock(&sender_lock);
}

// /* file_data api functions */
// void 
// set_data_name (struct file_data *data, char *data_name) {
// 	data->file_name = data_name;
// }
// char *
// get_data_name (struct file_data *data) {
// 	return data->file_name;
// }
// void 
// set_data_buf (struct file_data *data, char *data_buf) {
// 	data->file_buf = data_buf;
// }
// char *
// get_data_buf (struct file_data *data) {
// 	return data->file_buf;
// }
// void 
// set_data_size (struct file_data *data, int data_size) {
// 	data->file_size = data_size;
// }
// int 
// get_data_size (struct file_data *data) {
// 	return data->file_size;
// }
// struct file_data *
// set_data (struct file_data *data, struct file *file) {
// 	data->file_name = file->file_name;
// 	data->file_buf = file->file_buf;
// 	data->file_size = file->file_size;
// 	return data;
// }
// struct file_data *
// get_data (struct file *file) {
// 	struct file_data *data;
// 	data->file_name = file->file_name;
// 	data->file_buf = file->file_buf;
// 	data->file_size = file->file_size;
// 	return data;
// }

/* file_data api functions */
struct file_data *
cpy_lookup_sync (char *file_name) {
	pthread_mutex_lock(&l);
	struct file *file = cache_lookup(cache, file_name);
	if (file==NULL) {
		// printf("%s not found \n", file_name);
		pthread_mutex_unlock(&l);
		return NULL;
	}
	struct file_data *ret = file_data_init();
	// printf("%s found in cache \n", file_name);
	// ret->file_name = memcpy(ret->file_name, file->file_name, strlen(file->file_name)+1);
	// ret->file_buf = memcpy(ret->file_buf, file->file_buf, strlen(file->file_buf)+1);
	memcpy(ret->file_name, file->file_name, strlen(file->file_name)+1);
	memcpy(ret->file_buf, file->file_buf, strlen(file->file_buf)+1);
	// printf("success memcpy \n");
	ret->file_size = file->file_size;
	pthread_mutex_unlock(&l);
	return ret;
}
int
cpy_insert_sync (struct file_data *data)  {
	pthread_mutex_lock(&l);
	int ret = cache_insert(cache, file_init(data->file_name,
											data->file_buf,
											data->file_size));
	pthread_mutex_unlock(&l);
	return ret;
}
struct file_data *
data_lookup_sync (char *file_name) {
	pthread_mutex_lock(&l);
	struct file *file = cache_lookup(cache, file_name);
	struct file_data *ret = file_data_init();
	ret->file_name = file_name;
	ret->file_buf = file->file_buf;
	ret->file_size = file->file_size;
	pthread_mutex_unlock(&l);
	return ret;
}