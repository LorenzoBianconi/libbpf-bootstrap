// SPDX-License-Identifier: GPL-2.0-only
/*
 * This program implements a pMTU discovery responder in eBPF.
 * The idea is to replace the OVN check_packet_length action creating a
 * lpm_trie map in order to associate network addresses to specific MTUs.
 * E.g:
 *
 * $./xdp_check_mtu eth0 192.168.0.0/24:100 192.168.1.0/24:101 \
 *			 192.168.2.0/24:102
 *
 * xdp_check_mtu will send an ICMP error msg (need to frag) if the destination
 * belongs to a given IP network and the packet size is greater than the
 * specified one (MTU + 14).
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
		"%s: %s [-Shd] -M <mtu> -D <interface>\n"
		"OPTS:\n"
		"    -S    use skb-mode\n",
		__func__, prog);
}

int main(int argc, char **argv)
{
	struct xdp_check_mtu_bpf *skel;
	int opt, err = -1, mtu = -1;
	struct bpf_program *prog;
	bool debug = false;

	while ((opt = getopt(argc, argv, "hSdD:M:")) != -1) {
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
		case 'D':
			if_index = if_nametoindex(optarg);
			if (!if_index) {
				fprintf(stderr,
					"Failed to translate interface name: %s\n",
					optarg);
				return -1;
			}
			break;
		case 'M':
			mtu = strtol(optarg, NULL, 10);
			if (mtu < 0) {
				fprintf(stderr,
					"Failed to translate mtu: %s\n",
					optarg);
				return -1;
			}
			break;
		default:
			break;
		}
	}

	if (!(flags & XDP_FLAGS_SKB_MODE))
		flags |= XDP_FLAGS_DRV_MODE;

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
		return -1;
	}

	skel->bss->debug = debug;
	skel->bss->mtu = mtu;
	prog = mtu > 0 ? skel->progs.xdp_check_mtu : skel->progs.xdp_dummy;

	if (bpf_xdp_attach(if_index, bpf_program__fd(prog), flags, NULL) < 0) {
		fprintf(stderr, "Failed to load XDP program\n");
		goto out_destroy;
	}
	err = 0;

	while (!exiting)
		sleep(1);

	bpf_xdp_attach(if_index, -1, flags, NULL);
out_destroy:
	xdp_check_mtu_bpf__destroy(skel);
	return err;
}
