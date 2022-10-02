/*
 * Author: pamusuo@purdue.edu (Paschal Amusuo)
 *
 * Testing using mutated packets
 */

#include "fm_testing.h"
#include <dlfcn.h>

struct config;

struct fm_instance *fm_instance_new(void) {
    return calloc(1, sizeof(struct fm_instance));
}

int fm_instance_init(struct fm_instance *instance,
		     const struct config *config) {
    fm_interface_init_t init;
	char *error;

	instance->handle = dlopen(config->fm_filename,
				  RTLD_NOW | RTLD_LOCAL | RTLD_NODELETE |
				  RTLD_DEEPBIND);
	if (!instance->handle)
		die("%s\n", dlerror());
	dlerror();  /* clear any existing error */

	init = dlsym(instance->handle, "fm_interface_init");
	error = dlerror();
	if (error)
		die("%s\n", error);

	init(&instance->fm_interface);
	return STATUS_OK;
}

void fm_instance_free(struct fm_instance *instance) {
    if (!instance)
		return;

	instance->fm_interface.free();

	if (instance->handle)
		dlclose(instance->handle);

	memset(instance, 0, sizeof(*instance));
	free(instance);
}
