#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h>
#include <stdio.h>
#include <gssapi/gssapi.h>
#include <unistd.h>
#include <net/if.h>
#if defined(HAVE_IF_TUN)
#include <linux/if_tun.h>
#endif
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <syslog.h>
#include <ev.h>
#define GSSVPN_SERVER
#include "gssvpn.h"

struct conn * clients_ip[255];
struct conn * clients_ether[255];
gss_cred_id_t srvcreds;
int tapmtu = 1500;
int verbose = 1;
int reapclients = 36000;

int tapfd, netfd;
const uint64_t ether_broadcast = 0xffffffffffffffff;
const uint64_t ether_empty = 0x0000000000000000;

int get_server_creds(gss_cred_id_t * sco, char * service_name) {
	gss_buffer_desc name_buff;
	gss_name_t server_name;
	OM_uint32 maj_stat, min_stat;

	name_buff.value = service_name;
	name_buff.length = strlen(service_name);
	maj_stat = gss_import_name(&min_stat, &name_buff,
					(gss_OID) GSS_C_NT_HOSTBASED_SERVICE,
				   	&server_name);

	maj_stat = gss_acquire_cred(&min_stat, server_name, 0,
					GSS_C_NO_OID_SET, GSS_C_ACCEPT,
					sco, NULL, NULL);

	gss_release_name(&min_stat, &server_name);
	if(maj_stat != GSS_S_COMPLETE) {
		logit(1, "Error acquiring server credentials.");
		display_gss_err(maj_stat, min_stat);
		return -1;
	} else if(verbose)
		logit(-1, "Acquired credentials for %s", service_name);
	return 0;
}

void handle_shutdown(struct conn * client) {
	OM_uint32 min; 

	unlink_conn(client, CLIENT_ALL);
	if(client->context != GSS_C_NO_CONTEXT)
		gss_delete_sec_context(&min, &client->context, NULL); 

	free(client);
}

void tapfd_read_cb(struct ev_loop * loop, ev_io * ios, int revents) {
	uint8_t framebuf[1550], dstmac[6];
	size_t size = read(ios->fd, framebuf, 1550);
	gss_buffer_desc plaintext = { size, framebuf }; 
	time_t curtime = time(NULL);

	if(size == EAGAIN)
		return;

	memcpy(dstmac, framebuf, 6);
	if(memcmp(dstmac, &ether_broadcast, 6) == 0) {
		uint8_t i;
		for(i = 0; i < 255; i++) {
			struct conn * cur = clients_ether[i];
			while(cur) {
				cur->touched = curtime;
				send_packet(netfd, &plaintext, &cur->addr, PAC_DATA);
				cur = cur->ethernext;
			}
		}
		return;
	}
	uint8_t eh = hash(dstmac, 6);
	struct conn * client = clients_ether[eh];
	while(client && memcmp(client->mac, dstmac, 6) != 0)
		client = client->ethernext;
	if(!client) {
		if(verbose)
			logit(-1, "Received packet for unknown client");
		return;
	}

	send_packet(netfd, &plaintext, &client->addr, PAC_DATA);
}

void reap_cb(struct ev_loop *loop, ev_periodic *w, int revents) {
	uint8_t i;
	time_t curtime = time(NULL);
	for(i = 0; i < 255; i++) {
		struct conn * cur = clients_ip[i], * last = NULL;
		while(cur != NULL) {
			if(curtime - cur->touched >= reapclients) {
				struct conn * save = cur->ipnext;
				send_packet(netfd, NULL, &cur->addr, PAC_SHUTDOWN);
				unlink_conn(cur, CLIENT_ALL);
				handle_shutdown(cur);
				cur = save;
				continue;
			}

			last = cur;
			cur = cur->ipnext;
		}
	}
}

void handle_gssinit(struct conn * client, gss_buffer_desc * intoken) {
	gss_name_t client_name;
	gss_OID mech;
	gss_buffer_desc output, nameout, oidout;
	OM_uint32 flags, lmin, maj, min;

	if(client->gssstate == GSS_S_COMPLETE && 
					client->context != GSS_C_NO_CONTEXT)
		gss_delete_sec_context(&lmin, &client->context, NULL);
	client->context = GSS_C_NO_CONTEXT;

	maj = gss_accept_sec_context(&min, &client->context, srvcreds, intoken,
					NULL, &client_name, &mech, &output, &flags, NULL, NULL);
	if(maj != GSS_S_COMPLETE && maj != GSS_S_CONTINUE_NEEDED) {
		logit(1, "Error accepting security context from %s", client->ipstr);
		display_gss_err(maj, min);
		return;
	}
	client->gssstate = maj;
	if(maj == GSS_S_CONTINUE_NEEDED) {
		send_packet(netfd, &output, &client->addr, PAC_GSSINIT);
		return;
	}
	
	gss_display_name(&lmin, client_name, &nameout, NULL);
	gss_oid_to_str(&lmin, mech, &oidout);

	logit(0, "Authenticated connection for %s (%s) from %s",
					nameout.value, oidout.value,
					client->ipstr);
	gss_release_buffer(&lmin, &nameout);
	gss_release_buffer(&lmin, &oidout);
	gss_release_name(&lmin, &client_name);
	gss_release_oid(&lmin, &mech);
	send_packet(netfd, NULL, &client->addr, PAC_NETINIT);
}

void netfd_read_cb(struct ev_loop * loop, ev_io * ios, int revents) {
	gss_buffer_desc packet = GSS_C_EMPTY_BUFFER;
	char pac;
	struct sockaddr_in peer;
	struct conn * client;
	OM_uint32 min;

	if(recv_packet(netfd, &packet, &pac, &peer) != 0)
		return;

	client = get_conn(&peer);
	if(!client)
		return;

	if(client->gssstate == GSS_S_CONTINUE_NEEDED && pac != PAC_GSSINIT) {
		send_packet(netfd, NULL, &client->addr, PAC_GSSINIT);
		if(packet.length)
			gss_release_buffer(&min, &packet);
		return;
	}

	if(pac == PAC_DATA && memcmp(client->mac, &ether_empty,
		sizeof(ether_empty)) == 0) {
		send_packet(netfd, NULL, &client->addr, PAC_NETINIT);
		if(packet.length)
			gss_release_buffer(&min, &packet);
		return;
	}

	if(pac == PAC_DATA || pac == PAC_NETINIT) {
		if(pac == PAC_NETINIT) {
			uint8_t eh;
			if(packet.length != sizeof(client->mac)) {
				if(packet.value)
					gss_release_buffer(&min, &packet);
				logit(1, "Invalid netinit packet received");
			}
			memcpy(client->mac, packet.value, sizeof(client->mac));
			gss_release_buffer(&min, &packet);
			unlink_conn(client, CLIENT_ETHERNET);
			eh = hash(client->mac, sizeof(client->mac));
			client->ethernext = clients_ether[eh];
			clients_ether[eh] = client;
			send_packet(netfd, NULL, &client->addr, PAC_NOOP);
		}
		else if(packet.length > 0) {
			if(verbose)
				logit(-1, "Writing %d bytes to tap", packet.length);
			size_t s = write(tapfd, packet.value, packet.length);
			if(s < 0)
				logit(1, "Error writing to tap: %s", strerror(errno));
			else if(s < packet.length && verbose)
				logit(1, "Wrote less than expected to tap: %s < %s",
					s, packet.length);
			gss_release_buffer(&min, &packet);
		}
	}
	else if(pac == PAC_GSSINIT)
		handle_gssinit(client, &packet);
	else if(pac == PAC_SHUTDOWN) {
		unlink_conn(client, CLIENT_ALL);
		handle_shutdown(client);
	}

	if(packet.value)
		gss_release_buffer(&min, &packet);
	client->touched = time(NULL);	
}

int main(int argc, char ** argv) {
	int rc;
	ev_periodic reaper;
	ev_io tapio, netio;
	struct ev_loop * loop;
	openlog("gssvpnd", 0, LOG_DAEMON);

	rc = get_server_creds(&srvcreds, "gssvpn");
	if(rc != 0)
		return -1;

	tapfd = open_tap("tap0");
	if(tapfd < 0)
		return -1;

	netfd = open_net(2106);
	if(netfd < 0)
		return -1;

	memset(clients_ip, 0, sizeof(struct conn*) * 255);
	memset(clients_ether, 0, sizeof(struct conn*) * 255);

	loop = ev_default_loop(0);
	ev_io_init(&netio, netfd_read_cb, netfd, EV_READ);
	ev_io_start(loop, &netio);
	ev_io_init(&tapio, tapfd_read_cb, tapfd, EV_READ);
	ev_io_start(loop, &tapio);
	ev_periodic_init(&reaper, reap_cb, 0, reapclients, 0);
	ev_periodic_start(loop, &reaper);
	ev_run(loop, 0);

	close(tapfd);
	close(netfd);

	return 0;
}
