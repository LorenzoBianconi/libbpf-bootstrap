// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/stat.h>

#include "blink_tc.skel.h"

#define DEV_NAME	"enp2s0"
#define LR_DEV_IP	"::ffff:192.168.10.25"
#define OR_DEV_IP	"::ffff:192.168.10.26"

#define PORT		8888

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
	if (family == AF_INET) {
		struct sockaddr_in *sin = (void *)addr;

		memset(addr, 0, sizeof(*sin));
		sin->sin_family = AF_INET;
		sin->sin_port = htons(port);
		if (addr_str &&
		    inet_pton(AF_INET, addr_str, &sin->sin_addr) != 1)
			return -1;
		if (len)
			*len = sizeof(*sin);
		return 0;
	} else if (family == AF_INET6) {
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
	return -1;
}

#define save_errno_close(fd) ({ int __save = errno; close(fd); errno = __save; })
static int start_server(int family, int type, const char *addr_str,
			__u16 port, int timeout_ms)
{
	struct timeval timeout = { .tv_sec = 3 };
	struct sockaddr_storage addr;
	struct sockaddr *sa = (struct sockaddr *)&addr;
	socklen_t addrlen;
	int on = 1, fd;

	if (make_sockaddr(family, addr_str, port, &addr, &addrlen))
		return -1;

	fd = socket(sa->sa_family, type, 0);
	if (fd < 0)
		return -1;

	if (timeout_ms > 0) {
		timeout.tv_sec = timeout_ms / 1000;
		timeout.tv_usec = (timeout_ms % 1000) * 1000;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
		       sizeof(timeout)))
		return -1;

	if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout,
		       sizeof(timeout)))
		return -1;

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on)))
		return -1;

	if (bind(fd, sa, addrlen) < 0)
		goto error_close;

	if (type == SOCK_STREAM) {
		if (listen(fd, 1) < 0)
			goto error_close;
	}

	return fd;

error_close:
	save_errno_close(fd);
	return -1;
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
	int ifindex, err, sock;
	pid_t pid, sid;

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

	pid = fork();
	if (pid < 0) {
		fprintf(stderr, "fork syscall failed\n");
		return 1;
	}

	if (pid > 0) /* parent process */
		return 0;

	umask(0);
	sid = setsid();
	if (sid < 0) {
		fprintf(stderr, "setsid syscall failed\n");
		return 1;
	}

	chdir("/");

	sock = start_server(AF_INET, SOCK_STREAM, NULL, PORT, 0);
	if (sock < 0) {
		fprintf(stderr, "Failed to start server\n");
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

	/* close std descriptors */
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);

	while (!exiting) {
		struct sockaddr_storage client_addr;
		socklen_t client_addrlen;
		int client_sockfd;
		char buf[16] = {};
		size_t len;

		client_sockfd = accept(sock, (struct sockaddr *)&client_addr,
				       &client_addrlen);
		if (client_sockfd < 0)
			continue;

		len = recv(client_sockfd, buf, sizeof(buf), 0);
		if (len <= 0)
			continue;

		if (strstr(buf, "accept")) {
			skel->data->drop = false;
		} else if (strstr(buf, "drop")) {
			skel->data->drop = true;
		} else if (strstr(buf, "get")) {
			memset(buf, 0, sizeof(buf));
			sprintf(buf, "%d\n", skel->data->drop);
			send(client_sockfd, buf, strlen(buf), 0);
		}

		close(client_sockfd);
	}

	tc_opts.flags = tc_opts.prog_fd = tc_opts.prog_id = 0;
	err = bpf_tc_detach(&tc_hook, &tc_opts);
cleanup:
	if (hook_created)
		bpf_tc_hook_destroy(&tc_hook);
	blink_tc_bpf__destroy(skel);
	close(sock);

	return -err;
}
