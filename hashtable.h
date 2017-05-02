#ifndef _WC_H_
#define _WC_H_

/* DO NOT CHANGE THIS FILE */

/* Forward declaration of structure for the function declarations below. */
struct table;

struct table *table_init	(long size);
void table_output			(struct table *table);
void table_destroy			(struct table *table);
void print_table			(struct table *table);
void print_data				(struct table *table, char *word);
char *word_look_up 			(struct table *table, char *word);
struct file_data *look_up 	(struct table *table, char *word);
int insert_entry			(struct table *table, char *input_string, struct file_data *data);
int delete_entry 			(struct table *table, char *word);
long get_t_size 			(struct table *table);
long get_t_maxsize 			(struct table *table);

#endif /* _WC_H_ */