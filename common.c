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

extern int maxbufsize;
extern int verbose;

void log(int level, char * fmt, ...) {
	int err;
	va_list ap;
	
	va_start(ap, fmt);
	if(level = 0)
		err = LOG_INFO;
	else if(level == -1)
		err = LOG_DEBUG;
	else
		err = LOG_ERR;
	syslogv(err, fmt, ap);
	va_end(ap);
}

int open_net(short port) {
	struct sockaddr_in me;
	int s, rc;

	s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if(s < 0) {
		rc = errno;
		log(1, "Failed to open UDP socket: %s", strerror(rc));
		return -1;
	}

	memset(&me, 0, sizeof(me));
	me.sin_family = AF_INET;
	me.sin_port = htons(port);
	me.sin_addr.s_addr = htonl(INADDR_ANY);
	if(bind(s, &me, sizeof(me)) == -1) {
		rc = errno;
		close(s);
		log(1, "Failed to bind socket to port %d: %s",
					port, strerror(rc));
		return -1;
	}

	rc = getsockopt(s, SOL_IP, IP_MTU, &maxbuflen, &rc);
	if(rc < 0) {
		rc = errno;
		log(1, "Error getting MTU from UDP socket: %s",
					strerror(rc));
		close(s);
		return -1;
	}
	return s;
}

int recv_packet(int s, gss_buffer_desc * out, struct sockaddr_in * peer) {
	socklen_t ral = sizeof(ra);
	char * inbuff = malloc(maxbufsize);
	OM_uint16 lenfield, seqfield;
	int i, auth, bs = maxbufsize;
	char pacfield;
	struct pbuff * packet = NULL;

	size_t r = recvfrom(s, inbuff, bs, 0, peer, &ral);
	if(r < 0) {
		r = errno;
		log(1, "Error receiving packet from %s: %s",
				inet_ntoa(peer->s_addr), strerror(r));
		return -1;
	}
	memcpy(&lenfield, inbuff, 2);
	memcpy(&seqfield, inbuff + 2, 2);
	memcpy(&pacfield, inbuff + 4, 1);
	lenfield = ntohs(lenfield);
	seqfield = ntohs(seqfield);
	if(pacfield < 0) {
		if(lenfield > 0) {
			out->length = lenfield;
			out->value = malloc(lenfield);
			memcpy(out->value, inbuff + 5, lenfield);
		}
		return abs(pacfield);
	}

	packet = get_packet(peer, seqfield, lenfield, &bs);
	if(packet == NULL && lenfield <= bs) {
		out->length = lenfield;
		out->value = malloc(lenfield);
		memcpy(out->value, inbuff + 5, lenfield);
		free(inbuff);
		return 0;
	}

	memcpy(packet->buff + (bs * pacfield), inbuf + 5, r - 5);
	packet->have += r - 5;
	free(inbuf);

	if(packet->have == packet->len) {
		out->length = packet->len;
		out->value = malloc(packet->len);
		memcpy(out->value, packet->buf, out->len);
		free_packet(packet);
		return 0;
	}
	return 1;
}

int send_packet(int s, gss_buffer_desc * out,
			   struct sockaddr_in * peer, int bs) {
	char * inbuff = malloc(bs + 5);
	char * lock = out->value;
	char pac;
	OM_uint16 seq = get_seq(peer);
	OM_uint16 left = 0;
	if(out)
		left = out->length;
	size_t r;

	if(out->length)
		pac = out->length / bs;
		if(out->length % bs)
			pac++;
	}
	memcpy(inbuff, &left, 2);
	memcpy(inbuff + 2, &seq, 2);
	do {
		size_t tosend = (left > bs ? bs : left) + 5
		memcpy(inbuff + 4, &pac, 1);
		if(left == 0) {
			r = sendto(s, inbuff, 5, 0, peer, sizeof(struct sockaddr_in));
			break;
		}

		memcpy(inbuff + 5, lock, tosend - 5);
		r = sendto(s, inbuff, tosend, 0, peer, sizeof(struct sockaddr_in));
		if(r < 0) {
			log(1, "Error sending to %s: %s",
						inet_ntoa(peer->s_addr), strerror(errno));
			break;
		} else if(r < tosend) {
			log(1, "Sent less than expected to %s: %d < %d",
						inet_ntoa(peer->s_addr), r, tosend);
			break;
		}
		left -= r - 5;
		lock += r - 5;
		pac--;
	} while(pac);

	free(inbuff);
	return (r < 0 ? -1 : 0);
}

void gss_disp_loop(OM_uint32 status, OM_uint32 type) {
	gss_buffer_desc status_string = { 0, 0 };
	OM_uint32 context = 0, lmin, lmaj;

	do {
		lmaj = gss_display_status(&lmin, status, type, GSS_C_NO_OID,
						&context, &status_string);
		if(lmaj != GSS_S_COMPLETE)
			return;

		if(status_string.value) {
			log(1, "GSSAPI error %d: %.*s", status,
							status_string.length, status_string.value);
			gss_release_buffer(&lmin, &status_string);
		}
	} while(context != 0);
}

void display_gss_err(OM_uint32 major, OM_uint32 minor) {
	gss_disp_loop(major, GSS_C_GSS_CODE);
	gss_disp_loop(minor, GSS_C_MECH_CODE);
}

