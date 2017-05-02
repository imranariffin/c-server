#include "request.h"
#include "server_thread.h"
#include "common.h"

#define MAX_BUFF 10

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
struct monitor_t *monitor;
/* monitor functions */
struct monitor_t *monitor_init (struct server *sv, int n_threads);
void buff_write (int msg);
int buff_read ();
/* monitor helper functions */
int buff_full ();
int buff_empty ();
void print_buff ();

/* pthread pool */
struct pthread_pool_t {
	pthread_t *pthreads;
	int *ptids;
	int n_threads;
};
struct pthread_pool_t *ptpool;
/* pthread pool functions */
void Pthread_pool_init (struct pthread_pool_t *ptpool, int n_threads);
/* wrapper functions */
void Pthread_create(pthread_t *t, 
		const pthread_attr_t *attr, 
	    void *(*start_routine)(void *), 
	    void *arg);
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
static void
file_data_free(struct file_data *data)
{
	free(data->file_name);
	free(data->file_buf);
	free(data);
}

void *
dsr_stub (void *args) {
	while (1) {
		// do_server_request has to be atomic
		int connfd = buff_read();
		struct server *sv = monitor->sv;
		do_server_request(sv, connfd);
	}
}

static void
do_server_request(struct server *sv, int connfd)
{
	int ret;
	struct request *rq;
	struct file_data *data;

	data = file_data_init();

	/* fills data->file_name with name of the file being requested */
	rq = request_init(connfd, data);
	if (!rq) {
		file_data_free(data);
		return;
	}
	/* reads file, 
	 * fills data->file_buf with the file contents,
	 * data->file_size with file size. */
	ret = request_readfile(rq);
	if (!ret)
		goto out;
	/* sends file to client */
	request_sendfile(rq);
out:
	request_destroy(rq);
	file_data_free(data);
}

/* entry point functions */

struct server *
server_init(int nr_threads, int max_requests, int max_cache_size)
{
	struct server *sv;

	sv = Malloc(sizeof(struct server));
	sv->nr_threads = nr_threads;
	sv->max_requests = max_requests;
	sv->max_cache_size = max_cache_size;

	if (nr_threads > 0 || max_requests > 0 || max_cache_size > 0) {
		/* monitor is global */
		monitor = monitor_init(sv, nr_threads);

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
Pthread_create(pthread_t *t, 
		const pthread_attr_t *attr, 
	    void *(*start_routine)(void *), 
	    void *arg) {
    int rc = pthread_create(t, attr, start_routine, arg);
    assert(rc == 0);
}