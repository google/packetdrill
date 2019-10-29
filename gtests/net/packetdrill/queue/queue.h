/*
 * Queue implementation based on circular array.
 *
 * queue.h
 *
 *  Created on: 28 juil. 2013
 *      Author: Arnaud Schils
 */

#ifndef __QUEUE_H__
#define __QUEUE_H__

#include <stdlib.h>
#include <stdio.h>
#include "../types.h"

#define QUEUE_SIZE 255
#define STATUS_OK 0
#define STATUS_ERR -1

#ifndef NULL
#define NULL 0
#endif

struct queue_s{
	void *elements[QUEUE_SIZE];
	unsigned r, f;
};

typedef struct queue_s queue_t;

void queue_init(queue_t *queue);

void queue_free(queue_t *queue);

unsigned queue_size(queue_t *queue);

unsigned queue_is_empty(queue_t *queue);

int queue_front(queue_t *queue, void **element);

int queue_rear(queue_t *queue, void **element);

int queue_dequeue(queue_t *queue, void **element);

int queue_enqueue(queue_t *queue, void *element);


struct queue_s_val{
	u64 elements[QUEUE_SIZE];
	unsigned r, f;
};

typedef struct queue_s_val queue_t_val;

void queue_init_val(queue_t_val *queue);

void queue_free_val(queue_t_val *queue);

unsigned queue_size_val(queue_t_val *queue);

unsigned queue_is_empty_val(queue_t_val *queue);

int queue_front_val(queue_t_val *queue, u64 *element);

int queue_rear_val(queue_t_val *queue, u64 *element);

int queue_enqueue_val(queue_t_val *queue, u64 element);

int queue_dequeue_val(queue_t_val *queue, u64 *element);

#endif
