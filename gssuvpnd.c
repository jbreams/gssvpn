#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netdb.h>
#include <fcntl.h>
#include <stdio.h>
#include <poll.h>
#include <gssapi/gssapi.h>
#include <unistd.h>
#include <net/if.h>
#include <netinet/udp.h>
#if defined(HAVE_IF_TUN)
#include <linux/if_tun.h>
#endif
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <syslog.h>
#include "gssvpn.h"

struct conn * clients;
struct pbuff * packets;
gss_cred_id_t srvcreds;
int pbuffcount = 254;
int conncount = 254;
int pbuffperconn = 64;
int maxbufsize = 1500;
int verbose = 0;

struct conn * get_conn(struct sockaddr_in * peer) {
	int i;
	for(i = 0; i < conncount; i++) {
		if(memcmp(&clients[i].addr, peer,
			sizeof(struct sockaddr_in)) == 0)
				return &clients[i];
	}
	return NULL;
}

struct pbuff * get_packet(struct sockaddr_in * addr, OM_uint32 seq, 
				OM_uint32 len, int * bs) {
	struct conn * conn = get_conn(addr);
	struct packet * packet = NULL;
	int i;

	if(!conn)
		return NULL;

	for(i = 0; i < pbuffperconn; i++) {
		if(conn->packets[i] && conn->packets[i]->seq == seq)
			return conn->packets[i];
	}

	*bs = conn->bs;

	if(len < conn->bs - 9)
		return NULL;
	
	for(i = 0; i < pbuffcount; i++) {
		if(packets[i].conn == NULL)
			break;
	}

	packet = &packets[i];
	for(i = 0; i < pbuffperconn; i++) {
		if(conn->packets[i] == NULL) {
			conn->packets[i] = packet;
			break;
		}
	}

	packet->seq = seq;
	packet->len = len;
	packet->buf = malloc(len);
	packet->have = 0;
	return packet;
}

void free_packet(struct pbuff * buff) {
	struct conn * conn = buff->conn;
	int i;
	for(i = 0; i < pbuffperconn; i++) {
		if(conn->packets[i] == packet) {
			conn->packets[i] = NULL;
			break;
		}
	}

	free(buff->buf);
	memset(buff, 0, sizeof(struct pbuff));
}

OM_uint32 get_seq(struct sockaddr_in * peer) {
	int i;
	struct conn * client = get_conn(peer);
	if(client)
		return ++client->seq;
	return 0;
}

int get_server_creds(gss_cred_id_t * sco) {
	gss_buffer_desc name_buff;
	gss_name_t server_name;
	OM_uint32 maj_stat, min_stat;

	name_buff.value = SERVICE_NAME;
	name_buff.length = sizeof(SERVICE_NAME);
	maj_stat = gss_import_name(&min_stat, &name_buff,
					(gss_OID) GSS_C_NT_HOSTBASED_SERVICE,
				   	&server_name);

	maj_stat = gss_acquire_cred(&min_stat, server_name, 0,
					GSS_C_NO_OID_SET, GSS_C_ACCEPT,
					sco, NULL, NULL);

	gss_release_name(&min_stat, &server_name);
	if(maj_stat != GSS_S_COMPLETE) {
		display_gss_err(maj_stat, min_stat);
		return -1;
	} else if(verbose)
		log(-1, "Acquired credentials for SERVICE_NAME");
	return 0;
}

int open_tap(char * dev) {
	struct ifreq ifr;
	int tapfd = open("/dev/net/tun", O_RDWR), rc;

	if(tapfd < 0) {
		tapfd = errno;
		log(1, "Error opening TAP device: %s",
					strerror(tapfd));
		return -1;
	} else if(verbose)
		log(-1, "Opened TAP device to fd %d", tapfd);

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
	if(dev)
		strncpy(ifr.ifr_name, dev, sizeof(ifr.ifr_name));
	rc = ioctl(tapfd, TUNSETIFF, (void*)&ifr);
	if(rc < 0) {
		rc = errno;
		log(1, "Failed to configure TAP interface %s: %s",
					ifr.ifr_name, strerror(rc));
		close(tapfd);
		return -1;
	} else if(verbose)
		log(-1, "Configured TAP interface %s", ifr.ifr_name);

	int ts = socket(PF_UNIX, SOCK_STREAM, 0);
	ioctl(ts, SIOCGIFFLAGS, &ifr);
	ifr.ifr_flags |= IFF_UP;
	ioctl(ts, SIOCSIFFLAGS, &ifr);
	close(ts);

	return tapfd;
}

int process_frame(int s, gss_buffer_desc * plaintext, struct conn * client) {
	gss_buffer_desc crypted;
	OM_uint32 maj, min, confstate;
	int rc;

	maj = gss_wrap(&min, client->context, 1, GSS_C_QOP_DEFAULT, plaintext,
					&confstate, &crypted);
	if(maj != GSS_S_COMPLETE) {
		log(1, "Error wrapping packet for %s", inet_ntoa(client->addr.sa_addr));
		display_gss_err(maj, min);
		return -1;
	}

	rc = send_packet(s, &crypted, client->addr, client->bs);
	gss_release_buffer(&min, &crypted);
	return rc;
}

int client_gss_init(int s, gss_buffer_desc * packet, struct sockaddr_in * peer) {
	gss_OID doid;
	gss_name_t client;
	OM_uint32 maj, min, retflags;
	gss_buffer_desc contbuf;
	struct conn * client = get_conn(peer);
	int i;

	if(client == NULL) {
		for(i = 0; i < conncount; i++) {
			if(clients[i].context == GSS_C_NO_CONTEXT) {
				client = &clients[i];
				memset(client, 0, sizeof(struct conn));
				memcpy(&client.addr, peer, sizeof(struct sockaddr_in*));
				break;
			}
		}
	}

	if(client == NULL) {
		log(1, "No empty client slots available for %s",
				inet_ntoa(peer->s_addr));
		return -1;
	}

	maj = gss_accept_sec_context(&min, &client->context, srvcreds, &crypted,
				&contbuf, &retflags, NULL, NULL);
	client->gssstate = maj;
	if(maj == GSS_S_CONTINUE_NEEDED) {
		i = send_packet(s, &crypted, 0, peer, maxbufsize);
		gss_release_buffer(&min, &crypted);
	}
	else {
		crypted.value = malloc(maxbufsize);
		crypted.length = maxbufsize;
		i = send_packet(s, NULL, peer, maxbufsize);
		gss_release_buffer(&min, &crypted);
	}
	return i;
}

int client_net_init(int s, gss_buffer_desc * packet, struct sockaddr_in * peer) {
	OM_uint16 bs;
	char macdst[6];

	memcpy(macdst, packet->value, 6);
	memcpy(&bs, packet->value + 6, 2);
	bs = ntohs(bs);
}

int main(int argc, char ** argv) {
	int rc, tapfd, netfd, i;
	OM_uint32 maj, min, ret_flags;
	gss_OID doid;
	gss_name_t client;
	struct pollfd pfds[2];
	openlog("gssvpnd", 0, LOG_DAEMON);

	rc = get_server_creds(&srvcreds);
	if(rc != 0)
		return -1;

	tapfd = open_tap("tap0");
	if(tapfd < 0)
		return -1;

	netfd = open_tap(2106);
	if(netfd < 0)
		return -1;

	pfds[0].fd = tapfd;
	pfds[0].events = POLLIN;
	pfds[1].fd = netfd;
	pfds[1].events = POLLIN;

	if(verbose)
		log(-1, "Starting listener loop.");

	while(rc = poll(pfds, 2, -1)) {
		if(pfds[0].revents == POLLIN) {
			char dst[6];
			char * framebuf = malloc(1500);
			size_t framelen = read(tapfd, framebuf, 1500);
			memcpy(dst, framebuf + 8, 6);
			gss_buffer_desc plaintext;
			plaintext.length = framelen;
			planetext.value = framebuf;
			for(i = 0; i < conncount; i++) {
				if(memcmp(dst, 0xffffffffffffLL, 6) == 0)
					process_frame(netfd, &plaintext, &clients[i]);
				else if(memcmp(dst, clients[i].mac, 6) == 0) {
					process_frame(netfd, &plaintext, &clients[i]);
					break;
				}
			}
			memset(framebuf, 0, framelen);
			free(framebuf);
		}
		if(pfds[1].revents == POLLIN) {
			struct sockaddr_in peer;
			gss_buffer_desc crypted;
			rc = recv_packet(netfd, &crypted, &peer);
			struct conn * client = get_conn(peer);

			switch(rc) {
				case -2:
					client_gss_init(netfd, &crypted, &peer);
					break;
				case -3:

			}

			if(client == NULL) {
				
			}
		}
	}

}
