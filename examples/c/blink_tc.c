// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <net/if.h>
#include <arpa/inet.h>

#include "blink_tc.skel.h"

#define DEV_NAME	"enp2s0"
#define LR_DEV_IP	"::ffff:192.168.10.25"
#define OR_DEV_IP	"::ffff:192.168.10.26"

static volatile sig_atomic_t exiting = 0;

static void sig_int(int signo)
{
	exiting = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
{
	return vfprintf(stderr, format, args);
}

static int make_sockaddr(int family, const char *addr_str, __u16 port,
			 struct sockaddr_storage *addr, socklen_t *len)
{
	struct sockaddr_in6 *sin6 = (void *)addr;

	memset(addr, 0, sizeof(*sin6));
	sin6->sin6_family = AF_INET6;
	sin6->sin6_port = htons(port);
	if (addr_str &&
	    inet_pton(AF_INET6, addr_str, &sin6->sin6_addr) != 1)
		return -1;
	if (len)
		*len = sizeof(*sin6);
	return 0;
}

int main(int argc, char **argv)
{
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, tc_hook,
		.attach_point = BPF_TC_INGRESS);
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_opts,
		.handle = 1, .priority = 1);
	struct sockaddr_storage lr_sa;
	struct sockaddr_storage or_sa;
	bool hook_created = false;
	struct blink_tc_bpf *skel;
	int ifindex, err;

	ifindex = if_nametoindex(DEV_NAME);
	if (!ifindex) {
		fprintf(stderr, "Failed to find ifindex for %s\n", DEV_NAME);
		return 1;
	}

	if (make_sockaddr(AF_INET6, LR_DEV_IP, 0, &lr_sa, NULL)) {
		fprintf(stderr, "Invalid LR address %s\n", LR_DEV_IP);
		return 1;
	}

	if (make_sockaddr(AF_INET6, OR_DEV_IP, 0, &or_sa, NULL)) {
		fprintf(stderr, "Invalid LR address %s\n", OR_DEV_IP);
		return 1;
	}

	tc_hook.ifindex = ifindex;

	libbpf_set_print(libbpf_print_fn);

	skel = blink_tc_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	skel->rodata->lr_addr = ((struct sockaddr_in6 *)&lr_sa)->sin6_addr;
	skel->rodata->or_addr = ((struct sockaddr_in6 *)&or_sa)->sin6_addr;
	skel->data->drop = true; /* drop by default */

	err = blink_tc_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
	}

	/* The hook (i.e. qdisc) may already exists because:
	 *   1. it is created by other processes or users
	 *   2. or since we are attaching to the TC ingress ONLY,
	 *      bpf_tc_hook_destroy does NOT really remove the qdisc,
	 *      there may be an egress filter on the qdisc
	 */
	err = bpf_tc_hook_create(&tc_hook);
	if (!err)
		hook_created = true;

	if (err && err != -EEXIST) {
		fprintf(stderr, "Failed to create TC hook: %d\n", err);
		goto cleanup;
	}

	tc_opts.prog_fd = bpf_program__fd(skel->progs.blink_tc_ingress);
	err = bpf_tc_attach(&tc_hook, &tc_opts);
	if (err) {
		fprintf(stderr, "Failed to attach TC: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		err = errno;
		fprintf(stderr, "Can't set signal handler: %s\n", strerror(errno));
		goto cleanup;
	}

	while (!exiting) {
		fprintf(stderr, ".");
		sleep(1);
	}

	tc_opts.flags = tc_opts.prog_fd = tc_opts.prog_id = 0;
	err = bpf_tc_detach(&tc_hook, &tc_opts);
	if (err) {
		fprintf(stderr, "Failed to detach TC: %d\n", err);
		goto cleanup;
	}

cleanup:
	if (hook_created)
		bpf_tc_hook_destroy(&tc_hook);
	blink_tc_bpf__destroy(skel);

	return -err;
}
