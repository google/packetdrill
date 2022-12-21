/*
 * Author: pamusuo@purdue.edu (Paschal Amusuo)
 *
 * Testing using mutated packets
 */

#include "fm_testing.h"
#include <dlfcn.h>

struct config;

struct fm_packet {
	u8 *buffer;		/* data buffer: full contents of packet */
    u32 buffer_bytes;   /* bytes of space in data buffer */

	/* Layer 3 */
	u8 *ipv4;	/* start of IPv4 header, if present */
	u8 *ipv6;	/* start of IPv6 header, if present */

	/* Layer 4 */
	u8 *tcp;	/* start of TCP header, if present */
	u8 *udp;	/* start of UDP header, if present */
	u8 *icmpv4;	/* start of ICMPv4 header, if present */
	u8 *icmpv6;	/* start of ICMPv6 header, if present */
};

struct packet *handle_packet_mutation(struct packet *packet, struct fm_instance *fm_instance) {

	printf("ip_bytes: %d\n", packet->ip_bytes);
	printf("buffer_bytes: %d\n", packet->buffer_bytes);

	struct fm_packet fm_packet = {
		.buffer = (u8 *) packet->buffer,
		.buffer_bytes = packet->ip_bytes,
		.icmpv4 = (u8 *) packet->icmpv4,
		.icmpv6 = (u8 *) packet->icmpv6,
		.ipv4 = (u8 *) packet->ipv4,
		.ipv6 = (u8 *) packet->ipv6,
		.tcp = (u8 *) packet->tcp,
		.udp = (u8 *) packet->udp
	};

	struct fm_packet *mutated_fm_packet = fm_instance->fm_interface.mutate(&fm_packet, packet->fuzz_options);

	packet->buffer = mutated_fm_packet->buffer;
	packet->ip_bytes = mutated_fm_packet->buffer_bytes;
	packet->icmpv4 = (struct icmpv4 *) mutated_fm_packet->icmpv4;
	packet->icmpv6 = (struct icmpv6 *) mutated_fm_packet->icmpv6;
	packet->ipv4 = (struct ipv4 *) mutated_fm_packet->ipv4;
	packet->ipv6 = (struct ipv6 *) mutated_fm_packet->ipv6;
	packet->tcp = (struct tcp *) mutated_fm_packet->tcp;
	packet->udp = (struct udp *) mutated_fm_packet->udp;

	return packet;

}

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
