
/*
 * Author: pamusuo@purdue.edu (Paschal Amusuo)
 *
 * Testing using mutated packets
 */

#ifndef __FM_TESTING_H__
#define __FM_TESTING_H__

#include "packet.h"
#include "config.h"

struct config;

struct fm_interface {
	struct packet (*mutate)(struct packet *original);
	void (*free)();
};

typedef void (*fm_interface_init_t)(struct fm_interface *);

struct fm_instance {
	struct fm_interface fm_interface;
	void *handle;
};


/* Allocate a new fm_instance. */
struct fm_instance *fm_instance_new(void);

/* Load the fuzz mutation shared object and setup callback functions. */
int fm_instance_init(struct fm_instance *instance,
		     const struct config *config);

/* Delete a so_instance and its associated objects. */
void fm_instance_free(struct fm_instance *instance);

#endif /* __FM_TESTING_H__ */
