
/* KEY QUEUE STRUCT */
struct queue_t;
/* NODE */
struct node;

/* QUEUE METHODS */
struct queue_t * queue_init ();
struct node * pop(struct queue_t *queue);
void push(struct queue_t *queue, struct node *node);
void queue_destroy (struct queue_t *queue);
void print_queue(struct queue_t *queue);

/* NODE METHODS */
struct node * node_init(unsigned long key);