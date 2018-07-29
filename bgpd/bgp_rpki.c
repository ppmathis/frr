#define LIBSSH_LEGACY_0_4

#include <stdint.h>
#include <rtrlib/lib/ip.h>

#include "zebra.h"
#include "qobj.h"
#include "hook.h"
#include "module.h"
#include "command.h"
#include "libfrr.h"
#include "command.h"
#include "bgpd.h"
#include "bgp_advertise.h"
#include "bgp_attr.h"
#include "bgp_route.h"
#include "bgp_table.h"
#include "rtrlib/rtrlib.h"
#include "rtrlib/rtr_mgr.h"
#include "rtrlib/lib/ip.h"
#include "rtrlib/transport/tcp/tcp_transport.h"
#if defined(FOUND_SSH)
#include "rtrlib/transport/ssh/ssh_transport.h"
#endif

#ifndef VTYSH_EXTRACT_PL
#include "bgpd/bgp_rpki_clippy.c"
#endif

enum rpki_result {
	RPKI_SUCCESS = 0,
	RPKI_ERROR = -1
};

struct server {
	enum { TCP, SSH } type;
	uint8_t preference;

	struct rtr_socket *rtr_socket;
	struct tr_socket *tr_socket;
	union {
		struct tr_tcp_config *tcp;
		struct tr_ssh_config *ssh;
	} tr_config;

	enum rtr_mgr_status status;
};

struct rpki {
	uint8_t sflags;
#define RPKI_STATUS_RUNNING (1 << 0)
#define RPKI_STATUS_STOPPING (1 << 1)
#define RPKI_STATUS_STARTING (1 << 2)

	uint32_t polling_period;
	uint32_t expire_interval;
	uint32_t retry_interval;
	uint32_t initial_sync_timeout;

	struct {
		int rtrlib;
		int bgpd;
	} sync_sock;

	struct list *server;
	struct rtr_mgr_config *rtr_mgr_config;

	QOBJ_FIELDS
};
DEFINE_QOBJ_TYPE(rpki)

DEFINE_MGROUP(RPKI, "Resource Public Key Infrastructure (RPKI)")
DEFINE_MTYPE_STATIC(RPKI, RPKI, "RPKI structure")
DEFINE_MTYPE_STATIC(RPKI, RPKI_SERVER, "RPKI server structure")

#define RPKI_STR "RPKI information\n"

#define RPKI_POLLING_PERIOD_DEFAULT 3600
#define RPKI_EXPIRE_INTERVAL_DEFAULT 7200
#define RPKI_RETRY_INTERVAL_DEFAULT 600
#define RPKI_INITIAL_SYNC_TIMEOUT_DEFAULT 30

#define RPKI_DEBUG(...)                                                        \
	if (rpki_debug)                                                        \
		zlog_debug("RPKI: " __VA_ARGS__);

struct rpki *rpki = NULL;
static bool rpki_debug = true;
static struct cmd_node rpki_node = {RPKI_NODE, "%s(config-rpki)# ", 1};

static int rpki_start(struct rtr_mgr_group *group);
static int rpki_stop(void);
static void rpki_rtrlib_status_cb(const struct rtr_mgr_group *group, enum rtr_mgr_status status, const struct rtr_socket *socket, void *data);
static void rpki_rtrlib_update_cb(struct pfx_table *table, const struct pfx_record record, const bool added);
static int rpki_bgpd_sync_cb(struct thread *thread);

static void server_socket_init(struct server *server);
static void server_socket_free(struct server *server);
static const char *server_type_str(struct server *server);
static struct server *server_lookup(uint8_t preference);
static int server_cmp(struct server *c1, struct server *c2);
static void server_free(struct server *server);

static struct prefix *pfx_record_to_prefix(struct pfx_record *record);

static void *xmalloc(size_t size)
{
	return XMALLOC(MTYPE_RPKI_SERVER, size);
}

static void *xrealloc(void *ptr, size_t size)
{
	return XREALLOC(MTYPE_RPKI_SERVER, ptr, size);
}

static void xfree(void *ptr)
{
	XFREE(MTYPE_RPKI_SERVER, ptr);
}

static int rpki_create(void)
{
	rpki = XCALLOC(MTYPE_RPKI, sizeof(struct rpki));

	rpki->polling_period = RPKI_POLLING_PERIOD_DEFAULT;
	rpki->expire_interval = RPKI_EXPIRE_INTERVAL_DEFAULT;
	rpki->retry_interval = RPKI_RETRY_INTERVAL_DEFAULT;
	rpki->initial_sync_timeout = RPKI_INITIAL_SYNC_TIMEOUT_DEFAULT;

	rpki->server = list_new();
	rpki->server->cmp = (int (*)(void *, void *))server_cmp;
	rpki->server->del = (void (*)(void *))server_free;

	QOBJ_REG(rpki, rpki);

	return RPKI_SUCCESS;
}

static int rpki_clean(void)
{
	if (rpki) {
		QOBJ_UNREG(rpki);
		rpki_stop();
		list_delete_and_null(&rpki->server);
		XFREE(MTYPE_RPKI, rpki);
	}

	return RPKI_SUCCESS;
}

static int rpki_start(struct rtr_mgr_group *group)
{
	int ret;
	int fds[2];

	RPKI_DEBUG("initializing rtrlib manager with server %d",
		   group->preference);
	ret = rtr_mgr_init(&rpki->rtr_mgr_config, group, 1,
			   rpki->polling_period, rpki->expire_interval,
			   rpki->retry_interval, rpki_rtrlib_update_cb, NULL,
			   rpki_rtrlib_status_cb, NULL);
	if (ret == RTR_ERROR) {
		zlog_err("rpki_start: cannot initialize rtrlib manager");
		return RPKI_ERROR;
	}

	RPKI_DEBUG("starting rtrlib manager");
	ret = rtr_mgr_start(rpki->rtr_mgr_config);
	if (ret == RTR_ERROR) {
		zlog_err("rpki_start: cannot start rtrlib manager");
		rpki_stop();
		return RPKI_ERROR;
	}

	RPKI_DEBUG("initializing socket pair for synchronization");
	if (socketpair(PF_LOCAL, SOCK_DGRAM, 0, fds) != 0) {
		zlog_err("rpki_start: unable to open sync sockets");
		rpki_stop();
		return RPKI_ERROR;
	}

	rpki->sync_sock.rtrlib = fds[0];
	rpki->sync_sock.bgpd = fds[1];
	thread_add_read(bm->master, rpki_bgpd_sync_cb, NULL, rpki->sync_sock.bgpd, NULL);

	return RPKI_SUCCESS;
}

static int rpki_stop(void)
{
	if (rpki->rtr_mgr_config) {
		RPKI_DEBUG("stopping and freeing rtrlib manager");
		rtr_mgr_stop(rpki->rtr_mgr_config);
		rtr_mgr_free(rpki->rtr_mgr_config);
		rpki->rtr_mgr_config = NULL;
	}

	return RPKI_SUCCESS;
}

static int rpki_server_add(struct server *server)
{
	struct rtr_mgr_group group;

	server_socket_init(server);
	group.preference = server->preference;
	group.sockets_len = 1;
	group.sockets = &server->rtr_socket;

	if (rpki->rtr_mgr_config) {
		if (rtr_mgr_add_group(rpki->rtr_mgr_config, &group)
		    != RTR_SUCCESS) {
			zlog_err(
				"rpki_server_add: unable to add server to rtrlib manager");
			server_socket_free(server);
			return RPKI_ERROR;
		}
	} else {
		if (rpki_start(&group) != RPKI_SUCCESS) {
			zlog_err(
				"rpki_server_add: unable to start rpki to add first server");
			server_socket_free(server);
			return RPKI_ERROR;
		}
	}

	listnode_add(rpki->server, server);
	RPKI_DEBUG("added new server %d with type %s", server->preference,
		   server_type_str(server));

	return RPKI_SUCCESS;
}

static int rpki_server_remove(struct server *server)
{
	int ret;

	if (!rpki->rtr_mgr_config)
		return RPKI_SUCCESS;

	if (listcount(rpki->server) == 1) {
		ret = rpki_stop();
		if (ret != RPKI_SUCCESS)
			zlog_err(
				"rpki_server_remove: unable to stop rpki to remove last server");
		return ret;
	}

	if (rtr_mgr_remove_group(rpki->rtr_mgr_config, server->preference)
	    != RTR_SUCCESS) {
		zlog_err(
			"rpki_server_remove: unable to remove server from rtrlib manager");
		return RPKI_ERROR;
	}

	server_socket_free(server);
	listnode_delete(rpki->server, server);
	RPKI_DEBUG("removed server %d with type %s", server->preference,
		   server_type_str(server));

	return RPKI_SUCCESS;
}

static void rpki_bgpd_revalidate_node(struct bgp_node *bgp_node, afi_t afi,
				      safi_t safi)
{
	int ret;
	uint32_t num_labels = 0;
	mpls_label_t *label = NULL;
	struct bgp_adj_in *ain;
	struct bgp_info *bgp_info;

	for (ain = bgp_node->adj_in; ain; ain = ain->next) {
		bgp_info = bgp_node->info;
		if (bgp_info && bgp_info->extra) {
			label = bgp_info->extra->label;
			num_labels = bgp_info->extra->num_labels;
		}

		ret = bgp_update(ain->peer, &bgp_node->p, 0, ain->attr, afi,
				 safi, ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, NULL,
				 label, num_labels, 1, NULL);
		if (ret < 0) {
			bgp_unlock_node(bgp_node);
			return;
		}
	}
}

static void rpki_rtrlib_status_cb(const struct rtr_mgr_group *group, enum rtr_mgr_status status, const struct rtr_socket *socket, void *data)
{
	struct server *server = server_lookup(group->preference);
	if (!server || server->status == status)
		return;

	server->status = status;
	RPKI_DEBUG("server %d changed status: %s", group->preference, rtr_mgr_status_to_str(status));
}

static void rpki_rtrlib_update_cb(struct pfx_table *table, const struct pfx_record record, const bool added)
{
	ssize_t bytes;

	bytes = write(rpki->sync_sock.rtrlib, &record, sizeof(struct pfx_record));
	if (bytes != sizeof(struct pfx_record))
		zlog_warn("rpki_rtrlib_update_cb: unable to write prefix update to sync socket");
}

static int rpki_bgpd_sync_cb(struct thread *thread)
{
	ssize_t bytes;
	afi_t afi;
	safi_t safi;
	struct bgp *bgp;
	struct bgp_node *bgp_node;
	struct prefix *prefix;
	struct pfx_record record;
	struct list *matches;
	struct listnode *node, *nnode;

	thread_add_read(bm->master, rpki_bgpd_sync_cb, NULL,
			rpki->sync_sock.bgpd, NULL);

	bytes = read(rpki->sync_sock.bgpd, &record, sizeof(struct pfx_record));
	if (bytes != sizeof(struct pfx_record)) {
		zlog_warn(
			"rpki_bgpd_sync_cb: unable to read prefix update record from sync socket");
		return RPKI_ERROR;
	}

	prefix = pfx_record_to_prefix(&record);
	if (!prefix) {
		zlog_warn("rpki_bgpd_sync_cb: unable to convert prefix update record to prefix");
		return RPKI_ERROR;
	}

	afi = family2afi(prefix->family);
	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
		for (safi = SAFI_UNICAST; safi < SAFI_MAX; safi++) {
			if (!bgp->rib[afi][safi])
				continue;

			matches = list_new();
			matches->del = (void (*)(void *))bgp_unlock_node;
			bgp_table_range_lookup(bgp->rib[afi][safi], prefix, record.max_len, matches);

			for (ALL_LIST_ELEMENTS_RO(matches, node, bgp_node))
				rpki_bgpd_revalidate_node(bgp_node, afi, safi);

			list_delete_and_null(&matches);
		}
	}

	prefix_free(prefix);

	return RPKI_SUCCESS;
}

static int rpki_config_write(struct vty *vty)
{
	int write = 0;
	struct listnode *node;
	struct server *server;
	struct tr_tcp_config *tcp;
	struct tr_ssh_config *ssh;

	/* Module RPKI statement. */
	if (!rpki)
		return 0;
	vty_out(vty, "module rpki\n");
	write++;

	/* Polling period. */
	if (rpki->polling_period != RPKI_POLLING_PERIOD_DEFAULT)
		vty_out(vty, " polling-period %d\n", rpki->polling_period);

	/* Expire interval. */
	if (rpki->expire_interval != RPKI_EXPIRE_INTERVAL_DEFAULT)
		vty_out(vty, " expire-interval %d\n", rpki->expire_interval);

	/* Retry interval. */
	if (rpki->retry_interval != RPKI_RETRY_INTERVAL_DEFAULT)
		vty_out(vty, " retry-interval %d\n", rpki->retry_interval);

	/* Initial sync timeout. */
	if (rpki->initial_sync_timeout != RPKI_INITIAL_SYNC_TIMEOUT_DEFAULT)
		vty_out(vty, " initial-sync-timeout %d\n",
			rpki->initial_sync_timeout);

	/* Servers. */
	for (ALL_LIST_ELEMENTS_RO(rpki->server, node, server)) {
		vty_out(vty, " server %hhu ", server->preference);

		switch(server->type) {
		case TCP:
			tcp = server->tr_config.tcp;
			vty_out(vty, "%s tcp %s\n", tcp->host, tcp->port);

			break;

#if defined(FOUND_SSH)
		case SSH:
			ssh = server->tr_config.ssh;
			vty_out(vty, "%s ssh %u %s %s", ssh->host, ssh->port, ssh->username, ssh->client_privkey_path);
			if (ssh->server_hostkey_path)
				vty_out(vty, " %s", ssh->server_hostkey_path);
			vty_out(vty, "\n");

			break;
#endif
		}
	}

	return write;
}

static void server_socket_init(struct server *server)
{
	// TODO: Replace/remove assertions
	assert(server->tr_socket == NULL);
	assert(server->rtr_socket == NULL);

	server->tr_socket = XCALLOC(MTYPE_RPKI_SERVER, sizeof(struct tr_socket));
	server->rtr_socket = XCALLOC(MTYPE_RPKI_SERVER, sizeof(struct rtr_socket));
	server->rtr_socket->tr_socket = server->tr_socket;

	if (server->type == TCP)
		tr_tcp_init(server->tr_config.tcp, server->tr_socket);
#if defined(FOUND_SSH)
	else if (server->type == SSH)
		tr_ssh_init(server->tr_config.ssh, server->tr_socket);
#endif
}

static void server_socket_free(struct server *server)
{
	if (server->tr_socket) {
		tr_free(server->tr_socket);
		XFREE(MTYPE_RPKI_SERVER, server->tr_socket);
	}

	if (server->rtr_socket)
		XFREE(MTYPE_RPKI_SERVER, server->rtr_socket);
}

static struct server *server_new_tcp(const char *host, const char *port,
			  const uint8_t preference)
{
	struct server *server = XCALLOC(MTYPE_RPKI_SERVER, sizeof(struct server));
	struct tr_tcp_config *tr_tcp_config = XCALLOC(MTYPE_RPKI_SERVER, sizeof(struct tr_tcp_config));

	tr_tcp_config->host = XSTRDUP(MTYPE_RPKI_SERVER, host);
	tr_tcp_config->port = XSTRDUP(MTYPE_RPKI_SERVER, port);
	tr_tcp_config->bindaddr = NULL;

	server->type = TCP;
	server->preference = preference;
	server->tr_config.tcp = tr_tcp_config;

	return server;
}

#if defined(FOUND_SSH)
static struct server *server_new_ssh(const char *host, const unsigned int port,
			  const char *username, const char *client_privkey_path,
			  const char *server_hostkey_path,
			  const uint8_t preference)
{
	struct server *server = XMALLOC(MTYPE_RPKI_SERVER, sizeof(struct server));
	struct tr_ssh_config *tr_ssh_config = XMALLOC(MTYPE_RPKI_SERVER, sizeof(struct tr_ssh_config));

	tr_ssh_config->host = XSTRDUP(MTYPE_RPKI_SERVER, host);
	tr_ssh_config->port = port;
	tr_ssh_config->bindaddr = NULL;
	tr_ssh_config->username = XSTRDUP(MTYPE_RPKI_SERVER, username);
	tr_ssh_config->client_privkey_path = XSTRDUP(MTYPE_RPKI_SERVER, client_privkey_path);
	tr_ssh_config->server_hostkey_path = XSTRDUP(MTYPE_RPKI_SERVER, server_hostkey_path);

	server->type = SSH;
	server->preference = preference;
	server->tr_config.ssh = tr_ssh_config;

	return server;
}
#endif

static const char *server_type_str(struct server *server)
{
	switch (server->type) {
	case TCP:
		return "TCP";
	case SSH:
		return "SSH";
	default:
		return "Unknown";
	}
}

static struct server *server_lookup(uint8_t preference)
{
	struct server *server = NULL;
	struct listnode *node, *nnode;

	for (ALL_LIST_ELEMENTS(rpki->server, node, nnode, server)) {
		if (server->preference == preference)
			break;

	}

	return server;
}

static int server_cmp(struct server *c1, struct server *c2)
{
	return c1->preference > c2->preference ? 1 : -1;
}

static void server_free(struct server *server) {
	if (server->tr_socket && server->rtr_socket)
		server_socket_free(server);

	if (server->type == TCP) {
		XFREE(MTYPE_RPKI_SERVER, server->tr_config.tcp->host);
		XFREE(MTYPE_RPKI_SERVER, server->tr_config.tcp->port);
		XFREE(MTYPE_RPKI_SERVER, server->tr_config.tcp);
	}
#if defined (FOUND_SSH)
	else {
		XFREE(MTYPE_RPKI_SERVER, server->tr_config.ssh->host);
		XFREE(MTYPE_RPKI_SERVER, server->tr_config.ssh->username);
		XFREE(MTYPE_RPKI_SERVER, server->tr_config.ssh->client_privkey_path);
		XFREE(MTYPE_RPKI_SERVER, server->tr_config.ssh->server_hostkey_path);
		XFREE(MTYPE_RPKI_SERVER, server->tr_config.ssh);
	}
#endif

	XFREE(MTYPE_RPKI_SERVER, server);
}

static struct prefix *pfx_record_to_prefix(const struct pfx_record *record)
{
	struct prefix *prefix = prefix_new();

	prefix->prefixlen = record->min_len;
	if (record->prefix.ver == LRTR_IPV4) {
		prefix->family = AF_INET;
		lrtr_ipv4_addr_convert_byte_order(record->prefix.u.addr4.addr,
						  &prefix->u.prefix4.s_addr,
						  TO_NETWORK_BYTE_ORDER);
	} else if (record->prefix.ver == LRTR_IPV6) {
		prefix->family = AF_INET6;
		lrtr_ipv6_addr_convert_byte_order(record->prefix.u.addr6.addr,
						  &prefix->u.prefix6.s6_addr32[0],
						  TO_NETWORK_BYTE_ORDER);
	} else {
		prefix_free(prefix);
		return NULL;
	}

	return prefix;
}

static struct pfx_record *prefix_to_pfx_record(const struct prefix *prefix)
{
	struct pfx_record *record =
		XCALLOC(MTYPE_RPKI_SERVER, sizeof(struct pfx_record));

	if (prefix->family == AF_INET) {
		record->prefix.ver = LRTR_IPV4;
		lrtr_ipv4_addr_convert_byte_order(prefix->u.prefix4.s_addr,
						  &record->prefix.u.addr4.addr,
						  TO_HOST_HOST_BYTE_ORDER);
	} else if (prefix->family == AF_INET6) {
		record->prefix.ver = LRTR_IPV6;
		lrtr_ipv6_addr_convert_byte_order(prefix->u.prefix6.s6_addr32,
						  &record->prefix.u.addr6.addr[0],
						  TO_HOST_HOST_BYTE_ORDER);
	} else {
		XFREE(MTYPE_RPKI_SERVER, record);
		return NULL;
	}

	record->min_len = prefix->prefixlen;
	record->max_len = prefix->prefixlen;

	return record;
}

DEFUN_NOSH (module_rpki,
	    module_rpki_cmd,
	    "module rpki",
	    MODULE_STR
	    "Resource Public Key Infrastructure (RPKI)\n")
{
	int ret;

	if (!rpki) {
		ret = rpki_create();
		if (ret < 0) {
			zlog_info("%% RPKI failed to create instance");
			return CMD_WARNING_CONFIG_FAILED;
		}
	}
	VTY_PUSH_CONTEXT(RPKI_NODE, rpki);

	return CMD_SUCCESS;
}

DEFUN (module_no_rpki,
       module_no_rpki_cmd,
       "no module rpki",
       NO_STR
       MODULE_STR
       "Resource Public Key Infrastructure (RPKI)\n")
{
	if (rpki)
		rpki_clean();

	return CMD_SUCCESS;
}

DEFPY (rpki_polling_period,
       rpki_polling_period_cmd,
       "polling-period (1-86400)$val",
       "Set polling period\n"
       "Polling period value in seconds. Default is 3600.\n")
{
	rpki->polling_period = val;

	return CMD_SUCCESS;
}

DEFUN(no_rpki_polling_period,
      no_rpki_polling_period_cmd,
      "no polling-period [(1-86400)]",
      NO_STR
      "Set polling period\n"
      "Polling period value in seconds. Default is 3600.\n")
{
	rpki->polling_period = RPKI_POLLING_PERIOD_DEFAULT;

	return CMD_SUCCESS;
}

DEFPY (rpki_expire_interval,
       rpki_expire_interval_cmd,
       "expire-interval (600-172800)$val",
       "Set expire interval\n"
       "Expire interval value in seconds. Default is 7200.\n")
{
	rpki->expire_interval = val;

	return CMD_SUCCESS;
}

DEFUN (no_rpki_expire_interval,
       no_rpki_expire_interval_cmd,
       "no expire-interval [(600-172800)]",
       NO_STR
       "Set expire interval\n"
       "Expire interval value in seconds. Default is 7200.\n")
{
	rpki->expire_interval = RPKI_EXPIRE_INTERVAL_DEFAULT;

	return CMD_SUCCESS;
}

DEFPY (rpki_retry_interval,
       rpki_retry_interval_cmd,
       "retry-interval (1-7200)$val",
       "Set retry interval\n"
       "Retry interval value in seconds. Default is 600.\n")
{
	rpki->retry_interval = val;

	return CMD_SUCCESS;
}

DEFUN (no_rpki_retry_interval,
       no_rpki_retry_interval_cmd,
       "no retry-interval [(1-7200)]",
       NO_STR
       "Set retry interval\n"
       "Retry interval value in seconds. Default is 600.\n")
{
	rpki->retry_interval = RPKI_EXPIRE_INTERVAL_DEFAULT;

	return CMD_SUCCESS;
}

DEFPY (rpki_initial_sync_timeout,
       rpki_initial_sync_timeout_cmd,
       "initial-sync-timeout (1-4294967295)$val",
       "Set timeout for initial synchronization of prefix data\n"
       "Timeout value in seconds. Default is 30.\n")
{
	rpki->initial_sync_timeout = val;

	return CMD_SUCCESS;
}

DEFUN (no_rpki_initial_sync_timeout,
       no_rpki_initial_sync_timeout_cmd,
       "no initial-sync-timeout [(1-4294967295)]",
       NO_STR
       "Set timeout for initial synchronization of prefix data\n"
       "Timeout value in seconds. Default is 30.\n")
{
	rpki->initial_sync_timeout = RPKI_INITIAL_SYNC_TIMEOUT_DEFAULT;

	return CMD_SUCCESS;
}

DEFPY (rpki_server,
       rpki_server_cmd,
       "server (1-255)$preference <A.B.C.D|WORD>$host"
       "<tcp$mode TCP_PORT"
       "|ssh$mode (1-65535)$ssh_port SSH_UNAME SSH_PRIVKEY [SSH_HOSTKEY]>",
       "Specify a RPKI server\n"
       "Unique preference value\n"
       "IP address of server\n" "Hostname of server\n"
       "Use TCP protocol\n"
       "TCP port number\n"
       "Use SSH protocol\n"
       "SSH port number\n"
       "SSH user name\n"
       "Path to own SSH private key\n"
       "Path to remote SSH host key\n")
{
	struct server *server;

	if (server_lookup(preference)) {
		vty_out(vty, "%% Preference conflict with existing server\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (strcmp(mode, "tcp") == 0) {
		server = server_new_tcp(host, tcp_port, preference);
	} else if (strcmp(mode, "ssh") == 0) {
#if defined(FOUND_SSH)
		server = server_new_ssh(host, ssh_port, ssh_uname, ssh_privkey,
				     ssh_hostkey, preference);
#else
		vty_out(vty, "SSH sockets are not supported. Please recompile rtrlib and FRR with SSH support, if you want to use it.")
		return CMD_WARNING_CONFIG_FAILED;
#endif
	}

	if (rpki_server_add(server) != RPKI_SUCCESS) {
		vty_out(vty, "%% RPKI failed to add new server\n");
		server_free(server);

		return CMD_WARNING_CONFIG_FAILED;
	}

	return CMD_SUCCESS;
}

DEFPY (no_rpki_server,
       no_rpki_server_cmd,
       "no server (1-255)$preference [<A.B.C.D|WORD>]"
       "[<tcp TCP_PORT|ssh (1-65535) SSH_UNAME SSH_PRIVKEY [SSH_HOSTKEY]>]",
       NO_STR
       "Specify a RPKI server\n"
       "Unique preference value\n"
       "IP address of server\n" "Hostname of server\n"
       "Use TCP protocol\n"
       "TCP port number\n"
       "Use SSH protocol\n"
       "SSH port number\n"
       "SSH user name\n"
       "Path to own SSH private key\n"
       "Path to remote SSH host key\n")
{
	struct server *server = server_lookup(preference);
	if (server) {
		rpki_server_remove(server);
		server_free(server);
	}

	return CMD_SUCCESS;
}

DEFUN (show_rpki_prefix_table,
       show_rpki_prefix_table_cmd,
       "show rpki prefix-table",
       SHOW_STR
       RPKI_STR
       "Show validated prefixes received from RPKI servers\n")
{
	// TODO: Implement command

	return CMD_SUCCESS;
}

DEFPY (show_rpki_prefix,
       show_rpki_prefix_cmd,
       "show rpki prefix [A.B.C.D/M|X:X::X:X/M]$prefix",
       SHOW_STR
       RPKI_STR
       "Show RPKI validation state for prefix\n")
{
	struct pfx_record *query;
	struct pfx_record *records;
	struct pfxv_state state;

	if (!rpki || !rpki->rtr_mgr_config)
		return CMD_SUCCESS;

	if (!rtr_mgr_conf_in_sync(rpki->rtr_mgr_config)) {
		vty_out(vty, "%% No active synchronization with RPKI server\n");
		return CMD_WARNING;
	}

	query = prefix_to_pfx_record(prefix);

	records = XMALLOC(MTYPE_RPKI_SERVER, sizeof(struct pfx_record));
	pfx_table_validate_r(rpki->rtr_mgr_config->pfx_table, &records, 1, 0, query, 24, &state);

	return CMD_SUCCESS;
}

DEFUN (show_rpki_server,
       show_rpki_server_cmd,
       "show rpki server",
       SHOW_STR
       RPKI_STR
       "Show configured servers\n")
{
	struct server *server;
	struct listnode *node;

	// TODO: Show status
	// TODO: Show complete configuration
	for (ALL_LIST_ELEMENTS_RO(rpki->server, node, server)) {
		if (server->type == TCP) {
			vty_out(vty, "host: %s port: %s\n",
				server->tr_config.tcp->host,
				server->tr_config.tcp->port);
		}
#if defined(FOUND_SSH)
		else if (server->type == SSH) {
			vty_out(vty, "host: %s port: %u\n",
				server->tr_config.ssh->host,
				server->tr_config.ssh->port);
		}
#endif
	}

	return CMD_SUCCESS;
}

static int bgp_rpki_init(struct thread_master *master)
{
	install_node(&rpki_node, rpki_config_write);

	install_element(VIEW_NODE, &show_rpki_prefix_table_cmd);
	install_element(VIEW_NODE, &show_rpki_prefix_cmd);
	install_element(VIEW_NODE, &show_rpki_server_cmd);

	install_element(CONFIG_NODE, &module_rpki_cmd);
	install_element(CONFIG_NODE, &module_no_rpki_cmd);

	install_default(RPKI_NODE);
	install_element(RPKI_NODE, &rpki_polling_period_cmd);
	install_element(RPKI_NODE, &no_rpki_polling_period_cmd);
	install_element(RPKI_NODE, &rpki_expire_interval_cmd);
	install_element(RPKI_NODE, &no_rpki_expire_interval_cmd);
	install_element(RPKI_NODE, &rpki_retry_interval_cmd);
	install_element(RPKI_NODE, &no_rpki_retry_interval_cmd);
	install_element(RPKI_NODE, &rpki_initial_sync_timeout_cmd);
	install_element(RPKI_NODE, &no_rpki_initial_sync_timeout_cmd);
	install_element(RPKI_NODE, &rpki_server_cmd);
	install_element(RPKI_NODE, &no_rpki_server_cmd);

	return 0;
}

static int bgp_rpki_fini(void)
{
	return rpki_clean();
}

static int bgp_rpki_module_init(void)
{
	lrtr_set_alloc_functions(xmalloc, xrealloc, xfree);

	hook_register(frr_late_init, bgp_rpki_init);
	hook_register(frr_early_fini, bgp_rpki_fini);

	return 0;
}

FRR_MODULE_SETUP(.name = "bgpd_rpki", .version = "0.4.0",
		 .description = "bgpd RPKI module",
		 .init = bgp_rpki_module_init)