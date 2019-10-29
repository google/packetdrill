/*
 * queue.c
 *
 *  Created on: 28 juil. 2013
 *      Author: Arnaud Schils
 */

#include "queue.h"

void queue_init(queue_t *queue)
{
	queue->r = 0;
	queue->f = 0;
}

void queue_free(queue_t *queue)
{
	void *el;
	while(!queue_is_empty(queue)){
		queue_dequeue(queue, &el);
		free(el);
	}
}

unsigned queue_size(queue_t *queue)
{
	return (QUEUE_SIZE-queue->f+queue->r)%QUEUE_SIZE;
}

unsigned queue_is_empty(queue_t *queue)
{
	return queue->f == queue->r;
}

int queue_front(queue_t *queue, void **element)
{
	if(queue_is_empty(queue)){
		return STATUS_ERR;
	}
	*element = queue->elements[queue->f];
	return STATUS_OK;
}

int queue_rear(queue_t *queue, void **element){
	if(queue_is_empty(queue)){
		return STATUS_ERR;
	}
	if(queue->r != 0){
		*element = queue->elements[queue->r-1];
	}
	else{
		*element = queue->elements[QUEUE_SIZE];
	}
	return STATUS_OK;
}

int queue_dequeue(queue_t *queue, void **element){
	if(queue_is_empty(queue)){
		return STATUS_ERR;
	}
	void *temp = queue->elements[queue->f];
	queue->elements[queue->f] = NULL;
	queue->f = (queue->f+1%QUEUE_SIZE);
	*element = temp;
	return STATUS_OK;
}

int queue_enqueue(queue_t *queue, void *element){
	if(queue_size(queue) == QUEUE_SIZE-1){
		return STATUS_ERR;
	}
	queue->elements[queue->r] = element;
	queue->r = (queue->r+1)%QUEUE_SIZE;
	return STATUS_OK;
}

void queue_init_val(queue_t_val *queue){
	queue->r = 0;
	queue->f = 0;
}

void queue_free_val(queue_t_val *queue){
	u64 el;
	while(!queue_is_empty_val(queue)){
		queue_dequeue_val(queue, &el);
	}
}

unsigned queue_size_val(queue_t_val *queue){
	return (QUEUE_SIZE-queue->f+queue->r)%QUEUE_SIZE;
}

unsigned queue_is_empty_val(queue_t_val *queue){
	return queue->f == queue->r;
}

int queue_front_val(queue_t_val *queue, u64 *element){
	if(queue_is_empty_val(queue)){
		return STATUS_ERR;
	}
	*element = queue->elements[queue->f];
	return STATUS_OK;
}

int queue_rear_val(queue_t_val *queue, u64 *element){
	if(queue_is_empty_val(queue)){
		return STATUS_ERR;
	}
	if(queue->r != 0){
		*element = queue->elements[queue->r-1];
	}
	else{
		*element = queue->elements[QUEUE_SIZE];
	}
	return STATUS_OK;
}

int queue_enqueue_val(queue_t_val *queue, u64 element){
	if(queue_size_val(queue) == QUEUE_SIZE-1){
		return STATUS_ERR;
	}
	queue->elements[queue->r] = element;
	queue->r = (queue->r+1)%QUEUE_SIZE;
	return STATUS_OK;
}

int queue_dequeue_val(queue_t_val *queue, u64 *element){
	if(queue_is_empty_val(queue)){
		return STATUS_ERR;
	}
	*element = queue->elements[queue->f];
	queue->f = (queue->f+1%QUEUE_SIZE);
	return STATUS_OK;
}
