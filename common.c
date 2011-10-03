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
#include <netinet/in.h>
#if defined(HAVE_IF_TUN)
#include <linux/if_tun.h>
#endif
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <syslog.h>
#include <stdarg.h>
#include "gssvpn.h"

extern int verbose;

struct header {
	uint16_t len;
	uint16_t seq;
	uint8_t pac;
	uint8_t chunk;
};

struct pbuff {
	char buff[PBUFF_SIZE];
	struct header ph;
	uint16_t have;
	struct pbuff * next;
};

uint16_t seq = 0;
struct pbuff * packets[255];
int maxmtu = 1400;

struct pbuff * get_packet(struct header * ph) {
	uint8_t eh, ea[4];
	memcpy(ea, &ph->len, sizeof(uint16_t));
	memcpy(ea + sizeof(uint16_t), &ph->seq, sizeof(uint16_t));
	struct pbuff * pb;
	eh = hash(ea, 4);
	pb = packets[eh];
	while(pb && memcmp(ph, &pb->ph, sizeof(*ph) - 1) != 0)
		pb = pb->next;
	if(!pb) {
		pb = malloc(sizeof(struct pbuff));
		memset(pb, 0, sizeof(struct pbuff));
		pb->next = packets[eh];
		packets[eh] = pb;
		memcpy(&pb->ph, ph, sizeof(*ph));
		ph->chunk = 0;
	}
	return pb;
}

void free_packet(struct pbuff * pb) {
	uint8_t eh, ea[4];
	memcpy(ea, &pb->ph.len, sizeof(uint16_t));
	memcpy(ea + sizeof(uint16_t), &pb->ph.seq, sizeof(uint16_t));
	eh = hash(ea, 4);
	struct pbuff * last = NULL, *cur = packets[eh];
	while(cur && cur != pb) {
		last = cur;
		cur = cur->next;
	}

	if(!cur) {
		logit(1, "Trying to free orphaned packet");
		return;
	}

	if(last)
		last->next = cur->next;
	else
		packets[eh] = cur->next;
	free(cur);
}

void logit(int level, char * fmt, ...) {
	int err;
	va_list ap;
	
	if(level = 0)
		err = LOG_INFO;
	else if(level == -1)
		err = LOG_DEBUG;
	else
		err = LOG_ERR;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap); 
	fprintf(stderr, "\n");
	va_end(ap);
}

/* A "mixing table" of 256 distinct values, in pseudo-random order. */
unsigned char mixtable[256] = {
251, 175, 119, 215, 81, 14, 79, 191, 103, 49, 181, 143, 186, 157, 0,
232, 31, 32, 55, 60, 152, 58, 17, 237, 174, 70, 160, 144, 220, 90, 57,
223, 59, 3, 18, 140, 111, 166, 203, 196, 134, 243, 124, 95, 222, 179,
197, 65, 180, 48, 36, 15, 107, 46, 233, 130, 165, 30, 123, 161, 209, 23,
97, 16, 40, 91, 219, 61, 100, 10, 210, 109, 250, 127, 22, 138, 29, 108,
244, 67, 207, 9, 178, 204, 74, 98, 126, 249, 167, 116, 34, 77, 193,
200, 121, 5, 20, 113, 71, 35, 128, 13, 182, 94, 25, 226, 227, 199, 75,
27, 41, 245, 230, 224, 43, 225, 177, 26, 155, 150, 212, 142, 218, 115,
241, 73, 88, 105, 39, 114, 62, 255, 192, 201, 145, 214, 168, 158, 221,
148, 154, 122, 12, 84, 82, 163, 44, 139, 228, 236, 205, 242, 217, 11,
187, 146, 159, 64, 86, 239, 195, 42, 106, 198, 118, 112, 184, 172, 87,
2, 173, 117, 176, 229, 247, 253, 137, 185, 99, 164, 102, 147, 45, 66,
231, 52, 141, 211, 194, 206, 246, 238, 56, 110, 78, 248, 63, 240, 189,
93, 92, 51, 53, 183, 19, 171, 72, 50, 33, 104, 101, 69, 8, 252, 83, 120,
76, 135, 85, 54, 202, 125, 188, 213, 96, 235, 136, 208, 162, 129, 190,
132, 156, 38, 47, 1, 7, 254, 24, 4, 216, 131, 89, 21, 28, 133, 37, 153,
149, 80, 170, 68, 6, 169, 234, 151
};

char hash(char * in, int len) {
	char hash = len;
	int i;
	for(i = len; i > 0;)
		hash = mixtable[hash ^ in[--i]];
	return hash;
}

int open_tap(char * dev) {
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(struct ifreq));
#ifdef HAVE_IF_TUN
	int tapfd = open("/dev/net/tun", O_RDWR), rc;

	if(tapfd < 0) {
		tapfd = errno;
		logit(1, "Error opening TAP device: %s",
					strerror(tapfd));
		return -1;
	} else if(verbose)
		logit(-1, "Opened TAP device to fd %d", tapfd);

	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
	if(dev)
		strncpy(ifr.ifr_name, dev, sizeof(ifr.ifr_name));
	rc = ioctl(tapfd, TUNSETIFF, (void*)&ifr);
	if(rc < 0) {
		rc = errno;
		logit(1, "Failed to configure TAP interface %s: %s",
					ifr.ifr_name, strerror(rc));
		close(tapfd);
		return -1;
	} else if(verbose)
		logit(-1, "Configured TAP interface %s", ifr.ifr_name);
#else
	char path[255];
	snprintf(path, 255, "/dev/%s", dev);
	int tapfd = open(path, O_RDWR);
	if(tapfd < 0) {
		tapfd = errno;
		logit(1, "Error opening TAP device %s: %s",
					path, strerror(tapfd));
		return -1;
	}

	strncpy(ifr.ifr_name, dev, sizeof(ifr.ifr_name));
#endif

	int ts = socket(PF_UNIX, SOCK_STREAM, 0);
	ioctl(ts, SIOCGIFFLAGS, &ifr);
	ifr.ifr_flags |= IFF_UP;
	ioctl(ts, SIOCSIFFLAGS, &ifr);
	close(ts);

	return tapfd;
}

int open_net(short port) {
	struct sockaddr_in me;
	int s, rc;

	s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if(s < 0) {
		rc = errno;
		logit(1, "Failed to open UDP socket: %s", strerror(rc));
		return -1;
	}

	memset(&me, 0, sizeof(me));
	me.sin_family = AF_INET;
	me.sin_port = htons(port);
	me.sin_addr.s_addr = htonl(INADDR_ANY);
	if(bind(s, (struct sockaddr*)&me, sizeof(me)) == -1) {
		rc = errno;
		close(s);
		logit(1, "Failed to bind socket to port %d: %s",
					port, strerror(rc));
		return -1;
	}

	return s;
}

int recv_packet(int s, gss_buffer_desc * out, char * pacout,
		struct sockaddr_in * peer) {
	socklen_t ral = sizeof(struct sockaddr_in);
	struct header ph;
	char inbuff[PBUFF_SIZE + sizeof(ph)];
	struct pbuff * pb;

	size_t r = recvfrom(s, inbuff, PBUFF_SIZE + sizeof(ph), 0,
					(struct sockaddr*)peer, &ral);
	if(r < 0 || r < sizeof(ph)) {
		if(errno == EAGAIN)
			return 1;
		if(r < 0) {
			logit(1, "Error receiving packet %s", strerror(errno));
			return -1;
		}
		if(r < sizeof(ph)) {
			logit(1, "Packet is smaller than a header");
			return -1;
		}
	}
	memcpy(&ph, inbuff, sizeof(ph));
	
	ph.len = ntohs(ph.len);
	ph.seq = ntohs(ph.seq);
	*pacout = ph.pac;

	if(ph.len == 0)
		return 0;
	
	if(ph.len < maxmtu) {
		if(r - sizeof(ph) < ph.len) {
			logit(1, "Payload is smaller than expected");
			return -1;
		}
		out->length = ph.len;
		out->value = malloc(ph.len);
		memcpy(out->value, inbuff + sizeof(ph), out->length);
		if(verbose)
			logit(0, "Received packet of %d bytes", out->length);
		return 0;
	}

	pb = get_packet(&ph);
	size_t tocopy = r - sizeof(ph);
	memcpy(pb->buff + (maxmtu * ph.chunk), inbuff + sizeof(ph), tocopy);
	pb->have += tocopy;

	if(pb->have >= ph.len) {
		out->length = ph.len;
		out->value = malloc(ph.len);
		memcpy(out->value, pb->buff, ph.len);
		free_packet(pb);
		return 0;
	}

	if(verbose)
		logit(0, "Received partial %d packet %d of %d total - %d:%d %p",
			r - sizeof(ph), pb->have, ph.len, ph.chunk, ph.seq, pb);
	
	return 1;
}

int send_packet(int s, gss_buffer_desc * out,
		struct sockaddr_in * peer, char pac) {
	struct header ph;
	char outbuf[PBUFF_SIZE + sizeof(ph)];
	size_t sent = 0;
	ph.pac = pac;
	if(out && out->length)
		ph.len = htons(out->length);
	else
		ph.len = 0;
	if(ph.len > maxmtu)
		ph.seq = htons(seq++);
	ph.chunk = 0;

	if(!ph.len) {
		return sendto(s, &ph, sizeof(ph), 0, (struct sockaddr*)peer,
			sizeof(struct sockaddr_in));
	}

	do {
		size_t tocopy = out->length - sent, r;
		tocopy = tocopy > maxmtu ? maxmtu : tocopy;
		memcpy(outbuf, &ph, sizeof(ph));
		memcpy(outbuf + sizeof(ph), out->value + (maxmtu * ph.chunk), tocopy);
		r = sendto(s, outbuf, tocopy + sizeof(ph), 0, (struct sockaddr*)peer,
			sizeof(struct sockaddr_in));
		if(r < 0) {
			return -1;
		}
		sent += r - sizeof(ph);
		ph.chunk++;
		if(verbose)
			logit(0, "Send %d bytes in chunk %d out of %d bytes",
					r - sizeof(ph), ph.chunk - 1, out->length);
	} while(sent < out->length);

	return 0;
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
			logit(1, "GSSAPI error %d: %.*s", status,
							status_string.length, status_string.value);
			gss_release_buffer(&lmin, &status_string);
		}
	} while(context != 0);
}

void display_gss_err(OM_uint32 major, OM_uint32 minor) {
	gss_disp_loop(major, GSS_C_GSS_CODE);
	gss_disp_loop(minor, GSS_C_MECH_CODE);
}

