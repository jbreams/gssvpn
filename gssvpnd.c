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
int verbose = 0;
int reapclients = 36000;
int reappackets = 30;

int tapfd, netfd;
const char ether_broadcast[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

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
		logit(-1, "Acquired credentials for SERVICE_NAME");
	return 0;
}

int process_frame(gss_buffer_desc * plaintext, struct conn * client) {
	gss_buffer_desc crypted;
	OM_uint32 maj, min, confstate;
	int rc;

	maj = gss_wrap(&min, client->context, 1, GSS_C_QOP_DEFAULT, plaintext,
					&confstate, &crypted);
	if(maj != GSS_S_COMPLETE) {
		logit(1, "Error wrapping packet for %s", inet_ntoa(client->addr.sin_addr));
		display_gss_err(maj, min);
		return -1;
	}

	rc = send_packet(netfd, &crypted, &client->addr, client->bs, PAC_DATA);
	gss_release_buffer(&min, &crypted);
	return rc;
}

void handle_shutdown(struct conn * client) {
	struct pbuff * cp;
	uint8_t i;
	OM_uint32 min; 

	unlink_conn(client, CLIENT_ALL);
	if(client->context != GSS_C_NO_CONTEXT)
		gss_delete_sec_context(&min, &client->context, NULL); 

	for(i = 0; i < 255; i++) {
		cp = client->packets[i];
		while(cp) {
			struct pbuff * next = cp->next;
			free(cp);
			cp = next;
		}
	}
	free(client);
}

void tapfd_read_cb(struct ev_loop * loop, ev_io * ios, int revents) {
	char * framebuf = malloc(tapmtu), dstmac[6];
	size_t size = read(ios->fd, framebuf, tapmtu);
	gss_buffer_desc plaintext = { size, framebuf }; 
	time_t curtime = time(NULL);

	if(size == EAGAIN) {
		free(framebuf);
		return;
	}

	memcpy(dstmac, framebuf + 8, 6);
	if(memcmp(dstmac, ether_broadcast, 6) == 0) {
		uint8_t i;
		for(i = 0; i < 255; i++) {
			struct conn * cur = clients_ether[i];
			while(cur) {
				cur->touched = curtime;
				process_frame(&plaintext, cur);
				cur = cur->ethernext;
			}
		}
	} else {
		uint8_t eh = hash(dstmac, 6);
		struct conn * client = clients_ether[eh];
		while(client && memcmp(client->mac, dstmac, 6) != 0)
			client = client->ethernext;
		if(client) {
			process_frame(&plaintext, client);
			client->touched = curtime;
		}
	}
	
	free(framebuf);
}

/*
 * This is extremely extremely inefficient, like n^4, where n could be
 * any number between 0 and infinity. I'm thinking of adding a timeout for
 * each packet/client in the main event loop, but for now, this at least
 * gets the idea down on paper.
 */
void reap_cb(struct ev_loop *loop, ev_periodic *w, int revents) {
	uint8_t i;
	time_t curtime = time(NULL);
	for(i = 0; i < 255; i++) {
		struct conn * cur = clients_ip[i], * last = NULL;
		while(cur != NULL) {
			if(curtime - cur->touched >= reapclients) {
				unlink_conn(cur, CLIENT_ALL);
				handle_shutdown(cur);
				free(cur);
				if(last)
					cur = last;
				else
					cur = clients_ip[i];
				continue;
			}
			
			struct pbuff * pb;
			int j;
			for(j = 0; j < 255; j++) {
				for(pb = cur->packets[j]; pb != NULL; pb = pb->next) {
					if(curtime - pb->touched >= reappackets)
						free_packet(pb);
				}
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
	if(maj != GSS_S_COMPLETE || maj != GSS_S_CONTINUE_NEEDED) {
		logit(1, "Error accepting security context from %s",
					inet_ntoa(client->addr.sin_addr));
		display_gss_err(maj, min);
		return;
	}
	client->gssstate = maj;
	if(maj == GSS_S_CONTINUE_NEEDED) {
		send_packet(netfd, &output, &client->addr, client->bs, PAC_GSSINIT);
		return;
	}
	
	send_packet(netfd, NULL, &client->addr, client->bs, PAC_NOOP);
	
	gss_display_name(&lmin, client_name, &nameout, NULL);
	gss_oid_to_str(&lmin, mech, &oidout);

	logit(0, "Authenticated connection for %s (%s) from %s",
					nameout.value, oidout.value,
					inet_ntoa(client->addr.sin_addr));
	gss_release_buffer(&lmin, &nameout);
	gss_release_buffer(&lmin, &oidout);
	gss_release_name(&lmin, &client_name);
	gss_release_oid(&lmin, &mech);
}

void netfd_read_cb(struct ev_loop * loop, ev_io * ios, int revents) {
	gss_buffer_desc crypted = GSS_C_EMPTY_BUFFER;
	char pac;
	struct sockaddr_in peer;
	int rc = recv_packet(netfd, &crypted, &pac, &peer);
	OM_uint32 maj, min;
	struct conn * client;

	if(rc == 1)
		return;

	client = get_conn(&peer);
	if(!client)
		return;
	if(client->bs < 0 && pac != PAC_NETINIT) {
		logit(1, "Received packet without a buffer size.");
		if(crypted.length)
			gss_release_buffer(&min, &crypted);
		return;
	}

	if(client->gssstate == GSS_S_CONTINUE_NEEDED && pac != PAC_GSSINIT) {
		send_packet(netfd, NULL, &client->addr, client->bs, PAC_GSSINIT);
		if(crypted.length)
			gss_release_buffer(&min, &crypted);
		return;
	}

	if(pac == PAC_DATA) {
		gss_buffer_desc plaintext;

		maj = gss_unwrap(&min, client->context, &crypted,
					&plaintext, NULL, NULL);
		if(maj != GSS_S_COMPLETE) {
			logit(1, "Error unwrapping packet from %s",
					inet_ntoa(peer.sin_addr));
			display_gss_err(maj, min);
			gss_release_buffer(&min, &crypted);
			return;
		}
		if(plaintext.length > 0) {
			write(tapfd, plaintext.value, plaintext.length);
			gss_release_buffer(&min, &plaintext);
		}
	}
	else if(pac == PAC_GSSINIT)
		handle_gssinit(client, &crypted);
	else if(pac == PAC_NETINIT) {
		uint16_t bsout;
		gss_buffer_desc out = { sizeof(uint16_t), &bsout };
		unlink_conn(client, CLIENT_ETHERNET);
		client->bs = crypted.length - 6;
		client->ethernext = NULL;
		memcpy(client->mac, crypted.value, 6);
		char eh = hash(client->mac, 6);
		if(clients_ether[eh])
			client->ethernext = clients_ether[eh];
		clients_ether[eh] = client;
		bsout = htons(client->bs);
		send_packet(netfd, &out, &client->addr, client->bs, PAC_NETINIT);
	}
	else if(pac == PAC_SHUTDOWN)
		handle_shutdown(client);

	if(crypted.value)
		gss_release_buffer(&min, &crypted);
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
	ev_io_start(loop, &netio);
	ev_periodic_init(&reaper, reap_cb, 0,
		reapclients < reappackets ? reapclients:reappackets, 0);
	ev_periodic_start(loop, &reaper);
	ev_run(loop, 0);

	close(tapfd);
	close(netfd);

	return 0;
}
