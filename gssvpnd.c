#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netdb.h>
#include <pwd.h>
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
#ifdef DARWIN
#include <ev.h>
#else
#include <libev/ev.h>
#endif
#define GSSVPN_SERVER
#include "gssvpn.h"

struct conn * clients_ip[255];
struct conn * clients_ether[255];
gss_cred_id_t srvcreds = GSS_C_NO_CREDENTIAL;
int tapmtu = 1500;
int verbose = 1;
int reapclients = 36000;
char * authfile = NULL;

struct oc {
	gss_name_t client_name;
	struct oc * next;
} * ochead = NULL;

int tapfd = -1, netfd = -1;
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
	struct oc * cur = ochead;
	int nameeq = 0;

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

	while(cur != NULL &&
		gss_compare_name(&lmin, cur->client_name,
			client_name, &nameeq) == GSS_S_COMPLETE &&
		!nameeq)
		cur = cur->next;

	gss_display_name(&lmin, client_name, &nameout, NULL);
 
	if(!cur) {
		logit(0, "Connection from %s for %s is not authorized.",
					nameout.value, client->ipstr);
		send_packet(netfd, NULL, &client->addr, PAC_SHUTDOWN);
		handle_shutdown(client);
	} else {
		logit(0, "Accepted connection for %s from %s",
					nameout.value, client->ipstr);
		send_packet(netfd, NULL, &client->addr, PAC_NETINIT);
	}
	gss_release_buffer(&lmin, &nameout);
	gss_release_buffer(&lmin, &oidout);
	gss_release_name(&lmin, &client_name);
	gss_release_oid(&lmin, &mech);
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
	else if(pac == PAC_SHUTDOWN)
		handle_shutdown(client);

	if(packet.value)
		gss_release_buffer(&min, &packet);
	client->touched = time(NULL);	
}

void term_cb(struct ev_loop * l, ev_signal * w, int r) {
	OM_uint32 min;
	uint8_t i;
	struct oc * coc = ochead;
	
	for(i = 0; i < 255; i++) {
		struct conn * c = clients_ip[i];
		while(c) {
			struct conn * save = c->ipnext;
			send_packet(netfd, NULL, &c->addr, PAC_SHUTDOWN);
			handle_shutdown(c);
			c = save;
		}
	}

	close(tapfd);
	close(netfd);
	gss_release_credential(NULL, &srvcreds);

	while(coc) {
		struct oc * n = coc->next;
		gss_release_name(&min, &coc->client_name);
		free(coc);
		coc = n;
	}

	ev_break(l, EVBREAK_ALL);
}

void hup_cb(struct ev_loop * l, ev_signal * w, int r) {
	struct oc * lock = ochead;
	OM_uint32 maj, min;	
	FILE * f;
	char buff[4096];
	gss_buffer_desc namebuf = { 4096, buff };

	while(ochead) {
		struct oc * save = lock->next;
		gss_release_name(&min, &lock->client_name);
		free(lock);
		lock = save;
	}

	f = fopen(authfile, "r");
	if(f == NULL) {
		logit(1, "Error opening authorization file: %s", strerror(errno));
		ev_break(l, EVBREAK_ALL);
		return;
	}

	while(fgets(buff, 4096, f) != NULL) {
		size_t len = strlen(buff);
		if(buff[len - 1] != '\n') {
			logit(1, "Invalid name %s", buff);
			fclose(f);
			ev_break(l, EVBREAK_ALL);
			return;
		}

		lock = malloc(sizeof(struct oc));
		lock->next = ochead;

		len--;
		buff[len] = 0;
		namebuf.length = len;
		maj = gss_import_name(&min, &namebuf,
			GSS_C_NT_USER_NAME, &lock->client_name);	
		if(maj != GSS_S_COMPLETE) {
			logit(1, "Error importing name %s into auth list.", buff);
			display_gss_err(maj, min);
			fclose(f);
			free(lock);
			ev_break(l, EVBREAK_ALL);
		}

		ochead = lock;
	}
	fclose(f);
}

int main(int argc, char ** argv) {
	int rc;
	ev_periodic reaper;
	ev_io tapio, netio;
	ev_signal hup, term;
	struct ev_loop * loop;
	openlog("gssvpnd", 0, LOG_DAEMON);
	char ch;
	short port = 2106;
	struct oc * cur;
	uid_t dropto = 0;
	int daemonize = 0;

	while((ch = getopt(argc, argv, "ds:p:i:va:u:")) != -1) {
		switch(ch) {
			case 'v':
				verbose = 1;
				break;
			case 'p':
				port = atoi(optarg);
				break;
			case 'i':
				tapfd = open_tap("tap0");
				break;
			case 's':
				rc = get_server_creds(&srvcreds, optarg);
				if(rc != 0)
					return -1;
				break;
			case 'a': {
				FILE * testfile;
				authfile = strdup(optarg);
				testfile = fopen(authfile, "r");
				if(testfile == NULL) {
					logit(1, "Error opening authorization file %s",
						strerror(errno));
					return -1;
				}
				fclose(testfile);
				break;
			}
			case 'u': {
				struct passwd * u = getpwnam(optarg);
				if(!u) {
					logit(1, "Error doing user lookup for %s: (%s)",
						optarg, strerr(errno));
					return -1;
				}
				dropto = u->pw_uid;
			}
			case 'd':
				daemonize = 1;
		}
	}

	if(srvcreds == GSS_C_NO_CREDENTIAL) {
		rc = get_server_creds(&srvcreds, "gssvpn");
		if(rc != 0)
			return -1;
	}

	netfd = open_net(port);
	if(netfd < 0)
		return -1;

	if(tapfd < 0) {
		logit(1, "No tap device defined");
		return -1;
	}

	if(dropto)
		setuid(dropto);
	
	hupcb(loop, NULL, 0);
	if(daemonize)
		daemon(0, 0);
	
	memset(clients_ip, 0, sizeof(struct conn*) * 255);
	memset(clients_ether, 0, sizeof(struct conn*) * 255);

	loop = ev_default_loop(0);
	ev_io_init(&netio, netfd_read_cb, netfd, EV_READ);
	ev_io_start(loop, &netio);
	ev_io_init(&tapio, tapfd_read_cb, tapfd, EV_READ);
	ev_io_start(loop, &tapio);
	ev_periodic_init(&reaper, reap_cb, 0, reapclients, 0);
	ev_periodic_start(loop, &reaper);
	ev_signal_init(&hup, hup_cb, SIGHUP);
	ev_signal_start(loop, &hup);
	ev_signal_init(&term, term_cb, SIGTERM | SIGQUIT);
	ev_signal_start(loop, &term);
	ev_run(loop, 0);

	return 0;
}
