// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2017 Cavium, Inc.
 */
#include <linux/bpf.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/syscall.h>
#include <bpf/libbpf.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/resource.h>
#include <net/if.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <libgen.h>
#include "xdp_check_mtu.skel.h"

static struct env {
	bool verbose;
	long min_duration_ms;
} env;

struct ip_mtu_pair {
	__be32 dst;
	__u32 mtu;
};
static struct ip_mtu_pair *ip_mtu_list;

static int flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
static int if_index;

static volatile bool exiting = false;
static void sig_handler(int sig)
{
	exiting = true;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;

	return vfprintf(stderr, format, args);
}

static void bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur	= RLIM_INFINITY,
		.rlim_max	= RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		exit(1);
	}
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"%s: %s [-Shd] <interface> <IP0:mtu0> <IP1:mtu1>..\n"
		"OPTS:\n"
		"    -S    use skb-mode\n",
		__func__, prog);
}

static int parse_ip_mtu_pair(char **pair, int n_pair)
{
	int i;

	ip_mtu_list = (struct ip_mtu_pair *)calloc(n_pair,
						   sizeof(*ip_mtu_list));
	if (!ip_mtu_list)
		return 1;

	for (i = 0; i < n_pair; i++) {
		char *t0, *r0 = NULL;
		int j = 0;

		for (t0 = strtok_r(pair[i], ":", &r0); t0;
		     t0 = strtok_r(NULL, " ", &r0)) {
			if (!j) {
				__u32 addr;

				if (!inet_pton(AF_INET, t0, &addr))
					return 1;

				ip_mtu_list[i].dst = addr;
				j++;
			} else {
				long int mtu = strtol(t0, NULL, 10);

				if (!mtu)
					return 1;

				ip_mtu_list[i].mtu = mtu;
				break;
			}
		}
	}

	return 0;
}

int main(int argc, char **argv)
{
	struct xdp_check_mtu_bpf *skel;
	int i, opt, err = -1;
	bool debug = false;

	while ((opt = getopt(argc, argv, "hSd")) != -1) {
		switch (opt) {
		case 'S':
			flags |= XDP_FLAGS_SKB_MODE;
			break;
		case 'h':
			usage(basename(argv[0]));
			return 0;
		case 'd':
			debug = true;
			break;
		default:
			break;
		}
	}
	if (argc < optind + 2) {
		usage(basename(argv[0]));
		return 1;
	}

	if (!(flags & XDP_FLAGS_SKB_MODE))
		flags |= XDP_FLAGS_DRV_MODE;

	if_index = if_nametoindex(argv[optind]);
	if (!if_index) {
		fprintf(stderr, "Failed to translate interface name: %s\n",
			argv[optind]);
		return 1;
	}

	if (parse_ip_mtu_pair(&argv[optind + 1], argc - 1 - optind)) {
		fprintf(stderr, "Failed to parse IP-MTU pairs\n");
		usage(basename(argv[0]));
		goto out;
	}

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);
	/* Bump RLIMIT_MEMLOCK to create BPF maps */
	bump_memlock_rlimit();

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Load and verify BPF application */
	skel = xdp_check_mtu_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		goto out;
	}

	skel->bss->debug = debug;

	if (bpf_set_link_xdp_fd(if_index,
				bpf_program__fd(skel->progs.xdp_check_mtu),
				flags) < 0) {
		fprintf(stderr, "Failed to load XDP program\n");
		goto out_destroy;
	}

	for (i = 0; i < argc - 1 - optind; i++) {
		if (bpf_map_update_elem(bpf_map__fd(skel->maps.mtu_ipv4_match),
					&ip_mtu_list[i].dst,
					&ip_mtu_list[i].mtu, 0) < 0) {
			fprintf(stderr, "Failed to update BPF map\n");
			err = -1;
			goto out_unlink;
		}
	}

	while (!exiting)
		sleep(1);

out_unlink:
	bpf_set_link_xdp_fd(if_index, -1, flags);
out_destroy:
	xdp_check_mtu_bpf__destroy(skel);
out:
	free(ip_mtu_list);
	return err < 0 ? -err : 0;
}
