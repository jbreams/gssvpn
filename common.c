/*
 * Copyright 2011 Jonathan Reams
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "config.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netdb.h>
#include <fcntl.h>
#include <stdio.h>
#include <gssapi/gssapi.h>
#include <unistd.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#if defined(HAVE_IF_TUN)
#include <linux/if_tun.h>
#endif
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <syslog.h>
#include <stdarg.h>
#include "minilzo/minilzo.h"
#include "gssvpn.h"

extern int daemonize;
extern int verbose;

struct header {
	uint16_t sid;
	uint8_t pac;
};
uint8_t pbuff[8192];
uint8_t lzowrk[LZO1X_1_MEM_COMPRESS];

void logit(int level, char * fmt, ...) {
	int err;
	va_list ap;
	
	if(level == 0)
		err = LOG_INFO;
	else if(level == -1) {
		if(verbose == 0)
			return;
		err = LOG_DEBUG;
	}
	else
		err = LOG_ERR;
	va_start(ap, fmt);
	if(daemonize)
		vsyslog(err, fmt, ap);
	else {
		vfprintf(stderr, fmt, ap); 
		fprintf(stderr, "\n");
	}
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

uint8_t hash(uint8_t * in, int len) {
	uint8_t hash = len;
	int i;
	for(i = len; i > 0;)
		hash = mixtable[hash ^ in[--i]];
	return hash;
}

int open_tap(char ** dev) {
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(struct ifreq));
#ifdef HAVE_IF_TUN
	int tapfd = open("/dev/net/tun", O_RDWR), rc;

	if(tapfd < 0) {
		tapfd = errno;
		logit(1, "Error opening TAP device: %s",
					strerror(tapfd));
		return -1;
	}
	logit(-1, "Opened TAP device to fd %d", tapfd);

	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
	if(*dev)
		strncpy(ifr.ifr_name, *dev, sizeof(ifr.ifr_name));
	rc = ioctl(tapfd, TUNSETIFF, (void*)&ifr);
	if(rc < 0) {
		rc = errno;
		logit(1, "Failed to configure TAP interface %s: %s",
					ifr.ifr_name, strerror(rc));
		close(tapfd);
		return -1;
	}
	logit(-1, "Configured TAP interface %s", ifr.ifr_name);
#else
	int i, tapfd;
	char path[255];

	if(!dev) {
		*dev = malloc(sizeof("tapXXXX"));
		for(i = 0; i < 255 && tapfd < 0; i++) {
			snprintf(*dev, sizeof("tapXXXX"), "tap%d", i);
			snprintf(path, sizeof(path), "/dev/%s", *dev);
			tapfd = open(path, O_RDWR);
		}
	} else {
		snprintf(path, sizeof(path), "/dev/%s", *dev);
		tapfd = open(path, O_RDWR);
	}

	if(tapfd < 0) {
		tapfd = errno;
		logit(1, "Error opening TAP device %s: %s",
					*dev, strerror(tapfd));
		return -1;
	}

	strncpy(ifr.ifr_name, *dev, sizeof(ifr.ifr_name));
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

	if(lzo_init() != LZO_E_OK) {
		logit(1, "Error initialzing LZO library.");
		return -1;
	}

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

#ifdef IP_MTU_DISCOVER
	rc = IP_PMTUDISC_DO;
	setsockopt(s, IPPROTO_UDP, IP_MTU_DISCOVER, &rc, sizeof(int));
#endif

	return s;
}

int recv_packet(int s, gss_buffer_desc * out,
		char * pacout, struct sockaddr_in * peer, uint16_t * sid) {
	socklen_t ral = sizeof(struct sockaddr_in);
	struct header ph;
	OM_uint32 maj, min;
	uint8_t crbuf[8192];
	gss_buffer_desc crypted = { 8192, crbuf };
	gss_ctx_id_t ctx;
	int rc;

	ssize_t r = recvfrom(s, pbuff, sizeof(pbuff), 0,
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

	memcpy(&ph, pbuff, sizeof(ph));	
	ph.sid = ntohs(ph.sid);
	*pacout = ph.pac;
	*sid = ph.sid;

	logit(-1, "Received %d bytes from remote host - pac %d", r, ph.pac);

	if(r == sizeof(ph) || !out)
		return 0;

	rc = lzo1x_decompress_safe(pbuff + sizeof(ph), r - sizeof(ph),
		crypted.value, &crypted.length, lzowrk);
	if(rc != 0) {
		logit(1, "Error decompressing packet %d from %s:%d (%d bytes %d pac)",
			rc, inet_ntoa(peer->sin_addr), peer->sin_port, r- sizeof(ph), ph.pac);
		return -1;
	}

	ctx = get_context(peer, ph.sid);
	if(ctx != GSS_C_NO_CONTEXT && ph.pac != PAC_GSSINIT) {
		maj = gss_unwrap(&min, ctx, &crypted, out, NULL, NULL);
		if(maj != GSS_S_COMPLETE) {
			logit(1, "Error unwrapping packet from remote host");
			display_gss_err(maj, min);
			return -2;
		}
	} else {
		out->value = malloc(crypted.length);
		out->length = crypted.length;
		memcpy(out->value, crypted.value, crypted.length);
	}

	return 0;
}

int send_packet(int s, gss_buffer_desc * out,
		struct sockaddr_in * peer, char pac, uint16_t sid) {
	struct header ph;
	ssize_t sent;
	size_t tosend;
	ph.pac = pac;
	ph.sid = htons(sid);
	gss_ctx_id_t ctx = get_context(peer, sid);
	int rc;

	if(!(out && out->length)) {
		sent = sendto(s, &ph, sizeof(ph), 0,
			(struct sockaddr*)peer, sizeof(struct sockaddr_in));
		if(sent < 0) {
			logit(1, "Error sending header to remote host: %s",
				strerror(errno));
			return -1;
		}
		return 0;
	}

	if(ctx && pac != PAC_GSSINIT) {
		gss_buffer_desc pout;
		OM_uint32 maj, min;
		maj = gss_wrap(&min, ctx, 1, GSS_C_QOP_DEFAULT, out,
			NULL, &pout);
		if(maj != GSS_S_COMPLETE) {
			logit(1, "Error encrypting packet");
			display_gss_err(maj, min);
			return -2;
		}
		rc = lzo1x_1_compress(pout.value, pout.length,
			pbuff + sizeof(ph), &tosend, lzowrk);
		gss_release_buffer(&min, &pout);
	} else
		rc = lzo1x_1_compress(out->value, out->length,
			pbuff + sizeof(ph), &tosend, lzowrk);

	if(rc != 0) {
		logit(1, "Error compressing packet %d", rc);
		return -1;
	}
	
	memcpy(pbuff, &ph, sizeof(ph));
	tosend += sizeof(ph);
	
	sent = sendto(s, pbuff, tosend, 0, (struct sockaddr*)peer,
		sizeof(struct sockaddr_in));
	if(sent < 0) {
		logit(1, "Error sending PH to remote host: %s",
			strerror(errno));
		return -1;
	}
	logit(-1, "Sent %d bytes to remote host", sent);

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

