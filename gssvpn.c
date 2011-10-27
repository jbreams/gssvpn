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
#ifdef HAVE_IFADDRS_H
#include <ifaddrs.h>
#endif
#ifdef HAVE_IF_DL_H
#include <net/if_dl.h>
#endif
#ifdef HAVE_IF_PACKET_H
#include <linux/if_packet.h>
#endif
#include "libev/ev.h"
#include "gssvpn.h"

gss_ctx_id_t context = GSS_C_NO_CONTEXT;
OM_uint32 gssstate = GSS_S_CONTINUE_NEEDED;
int tapfd, netfd, verbose = 0, init = 0;
struct sockaddr_in server;
char * tapdev, *service, *hostname, *netinit_util = NULL;
ev_child netinit_child;
ev_timer init_retry, keepalive_timer;
ev_signal term;
ev_io tapio, netio;
int daemonize = 0, keepalive = 30;
ev_tstamp last_init_activity, last_keepalive = 0;
char * username = NULL;
char * netinit_args[258];
uint8_t mac[6];
gss_buffer_desc netinit_buffer;
uint16_t sessionid = 0;

gss_ctx_id_t get_context(struct sockaddr_in * peer, uint16_t sessid) {
	if(gssstate == GSS_S_COMPLETE)
		return context;
	return NULL;
}

void keepalive_cb(struct ev_loop * loop, ev_timer * iot, int revents) {
	ev_tstamp now = ev_now(loop);
	ev_tstamp timeout = last_keepalive + keepalive;
	if(timeout < now) {
		send_packet(netfd, NULL, &server, PAC_ECHO, sessionid);
		ev_timer_again(loop, iot);
	} else {
		iot->repeat = timeout - now;
		ev_timer_again(loop, iot);
	}
}

void netinit_cb(struct ev_loop * loop, ev_child * c, int revents) {
	ev_child_stop(loop, c);
	if(c->rstatus == 0) {
		ev_timer_stop(loop, &init_retry);
		if(ev_is_active(&keepalive_timer))
			ev_timer_stop(loop, &keepalive_timer);
		else
			ev_init(&keepalive_timer, keepalive_cb);
		last_keepalive = ev_now(loop);
		keepalive_cb(loop, &keepalive_timer, EV_TIMER);
		logit(0, "Netinit okay. Starting normal operation.");
		return;
	}

	logit(1, "Received error code from netinit util %d", c->rstatus);
	send_packet(netfd, NULL, &server, PAC_SHUTDOWN, sessionid);
	ev_break(loop, EVBREAK_ALL);
	init = 0;
}

int do_netinit(struct ev_loop * loop, gss_buffer_desc * in) {
	char * lock;
	pid_t pid;
	int argc = 0;

	if(!netinit_util) {
		init = 1;
		return 0;
	}

	init = 1;
	last_init_activity = ev_now(loop);
	lock = netinit_util + (strlen(netinit_util) - 1);
	while(*lock != '/' && lock != netinit_util)
		lock--;
	if(*lock == '/')
		lock++;

	netinit_args[argc++] = lock;
	netinit_args[argc++] = tapdev;
	netinit_args[argc++] = "init";

	if(in) {
		lock = (char*)in->value;
		while(lock - (char*)in->value < in->length && argc < 255) {
			char * save = lock;
			while(*lock != '\n' && lock - (char*)in->value < in->length)
				lock++;
			if(*lock == '\n') {
				*lock = 0;
				netinit_args[argc++] = save;
				lock++;
			}
		}
	}
	netinit_args[argc] = NULL;

	pid = fork();
	if(pid == 0) {
		close(tapfd);
		close(netfd);
		if(execv(netinit_util, netinit_args) < 0)
			exit(errno);
	} else {
		ev_child_init(&netinit_child, netinit_cb, pid, 0);
		ev_child_start(loop, &netinit_child);
	}

	return 0;
}

int do_gssinit(struct ev_loop * loop, gss_buffer_desc * in) {
	gss_name_t target_name;
	char prodid[512];
	gss_buffer_desc tokenout = { 512, &prodid };
	OM_uint32 min;

	ev_io_stop(loop, &tapio);

	tokenout.length = snprintf(prodid, 512, "%s@%s", service, hostname);
	gssstate = gss_import_name(&min, &tokenout, 
					(gss_OID)GSS_C_NT_HOSTBASED_SERVICE,
					&target_name);
	tokenout.value = NULL;
	tokenout.length = 0;

	if(context != GSS_C_NO_CONTEXT &&
		gssstate == GSS_S_COMPLETE)
		gss_delete_sec_context(&min, &context, NULL);
	gssstate = gss_init_sec_context(&min, GSS_C_NO_CREDENTIAL,
					&context, target_name, NULL,
					GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG | GSS_C_MUTUAL_FLAG,
					GSS_C_INDEFINITE, NULL, in, NULL, &tokenout,
					NULL, NULL);

	if(gssstate != GSS_S_COMPLETE && gssstate != GSS_S_CONTINUE_NEEDED) {
		if(context != GSS_C_NO_CONTEXT)
			gss_delete_sec_context(&min, &context, GSS_C_NO_BUFFER);
		display_gss_err(gssstate, min);
		return -1;
	}

	gss_release_name(&min, &target_name);
	if(tokenout.length) {
		int rc;
		rc = send_packet(netfd, &tokenout, &server, PAC_GSSINIT, sessionid);
		gss_release_buffer(&min, &tokenout);
		if(rc < 0)
			return -1;
	}
	ev_io_start(loop, &tapio);
	return 0;
}

void netfd_read_cb(struct ev_loop * loop, ev_io * ios, int revents) {
	int rc;
	char pac;
	struct sockaddr_in peer;
	gss_buffer_desc packet = GSS_C_EMPTY_BUFFER;
	OM_uint32 min;

	rc = recv_packet(netfd, &packet, &pac, &peer, &sessionid);
	if(rc == -2) {
		logit(1, "Reinitializing GSSAPI context");
		if(context != GSS_C_NO_CONTEXT) {
			gss_delete_sec_context(&min, &context, NULL);
			context = GSS_C_NO_CONTEXT;
		}
		do_gssinit(loop, NULL);
	}
	if(rc < 0)
		return;
	
	if(pac == PAC_DATA) {
		logit(-1, "Writing %d bytes to TAP", packet.length);
		ssize_t s = write(tapfd, packet.value, packet.length);
		if(s < 0)
			logit(1, "Error writing packet to tap: %s", strerror(errno));
	}
	else if(pac == PAC_NETINIT) {
		if(packet.length > 0) {
			memcpy(&netinit_buffer, &packet, sizeof(gss_buffer_desc));		
			do_netinit(loop, &packet);
		} else
			do_netinit(loop, NULL);
	} else if(pac == PAC_GSSINIT)
		do_gssinit(loop, &packet);
	else if(pac == PAC_SHUTDOWN)
		ev_break(loop, EVBREAK_ALL);
	else if(pac == PAC_NETSTART) {
		gss_buffer_desc macout = { sizeof(mac), mac };
		send_packet(netfd, &macout, &server, PAC_NETINIT, sessionid);
	}
	if(packet.length && pac != PAC_NETINIT)
		gss_release_buffer(&min, &packet);
}

void tapfd_read_cb(struct ev_loop * loop, ev_io * ios, int revents) {
	uint8_t inbuff[1550];
	gss_buffer_desc plaintext = { 1550, inbuff };
	OM_uint32 min;
	int rc;

	if(context == GSS_C_NO_CONTEXT || gssstate == GSS_S_CONTINUE_NEEDED) {
		logit(-1, "Dropping packet from tap");
		return;
	}

	plaintext.length = read(tapfd, inbuff, 1550);
	if(plaintext.length < 0) {
		logit(1, "Error receiving packet from TAP: %s",
			strerror(errno));
		return;
	}
	logit(-1, "Received packet from TAP of %d bytes", plaintext.length);

	rc = send_packet(netfd, &plaintext, &server, PAC_DATA, sessionid);
	if(rc == -2) {
		logit(0, "Reinitializing GSSAPI context");
		if(context != GSS_C_NO_CONTEXT) {
			gss_delete_sec_context(&min, &context, NULL);
			context = GSS_C_NO_CONTEXT;
		}
		do_gssinit(loop, NULL);
	}
	return;
}

void term_cb(struct ev_loop * loop, ev_signal * ios, int revents) {
	ev_signal_stop(loop, ios);
	ev_break(loop, EVBREAK_ALL);
}

int get_mac() {
#ifdef HAVE_IFADDRS_H
	struct ifaddrs * ifp, *cifp;
	if(getifaddrs(&ifp) < 0) {
		logit(1, "Error getting list of interfaces %m");
		return -1;
	}

	for(cifp = ifp;
#ifdef HAVE_IF_PACKET_H
		cifp && cifp->ifa_addr->sa_family == AF_PACKET &&
			strcmp(cifp->ifa_name, tapdev) != 0;
#else
		cifp && strcmp(cifp->ifa_name, tapdev) != 0;
#endif
		cifp = cifp->ifa_next);
	if(!cifp) {
		logit(1, "Couldn't find %s in list of interfaces", tapdev);
		freeifaddrs(ifp);
		return -1;
	}

#ifdef HAVE_IF_DL_H
	struct sockaddr_dl* sdl = (struct sockaddr_dl*)cifp->ifa_addr;
	memcpy(mac, LLADDR(sdl), sizeof(mac));
#elif defined(HAVE_IF_PACKET_H)
	struct sockaddr_ll* lll = (struct sockaddr_ll*)cifp->ifa_addr;
	memcpy(mac, lll->sll_addr, sizeof(mac));
#endif
	freeifaddrs(ifp);
#endif
	return 0;
}

void init_retry_cb(struct ev_loop * loop, ev_timer * w, int revents) {
	ev_tstamp now = ev_now(loop);
	ev_tstamp timeout = last_init_activity + 10;
	if(timeout < now) {
		if(gssstate != GSS_S_COMPLETE || init < 1) {
			logit(1, "Did not receive GSS packet from server. Retrying.");
			do_gssinit(loop, NULL);
			ev_timer_again(loop, w);
		}
		else
			ev_timer_stop(loop, w);
	} else {
		w->repeat = timeout - now;
		ev_timer_again(loop, w);	
	}
}

int main(int argc, char ** argv) {
	struct ev_loop * loop;
	char ch;
	short port = 0;
	struct hostent * hostinfo;
	OM_uint32 min;

	memset(&server, 0, sizeof(struct sockaddr_in));
	
	while((ch = getopt(argc, argv, "vh:p:s:i:a:u:e:")) != -1) {
		switch(ch) {
			case 'v':
				verbose = 1;
				break;
			case 'h':
				hostname = strdup(optarg);
				break;
			case 'p':
				port = atoi(optarg);
				break;
			case 's':
				service = strdup(optarg);
				break;
			case 'i':
				tapdev = strdup(optarg);
				break;
			case 'a': {
				if(access(optarg, R_OK|X_OK) < 0) {
					logit(1, "Unable to access %s for read/execute: %s",
						optarg, strerror(errno));
					return -1;
				}
				netinit_util = strdup(optarg);
				break;
			}
			case 'e':
				keepalive = atoi(optarg);
				break;
			case 'u':
				username = strdup(optarg);
				break;
		}
	}

	if(hostname == NULL) {
		logit(1, "Must enter hostname to connect to");
		return -1;
	}
	hostinfo = gethostbyname(hostname);
	if(hostinfo == NULL) {
		logit(1, "Unable to resolve %s: %s",
						hostname, strerror(errno));
		return -1;
	}

	if(service == NULL)
		service = strdup("gssvpn");
	if(port == 0)
		port = 2106;
	if(tapdev == NULL)
		tapdev = strdup("tap0");

	memset(&server, 0, sizeof(struct sockaddr_in));
	server.sin_family = AF_INET;
	memcpy(&server.sin_addr, hostinfo->h_addr, sizeof(server.sin_addr));
	server.sin_port = htons(port);

	netfd = open_net(0);
	if(netfd < 0)
		return -1;

	tapfd = open_tap(&tapdev);
	if(tapfd < 0)
		return -1;

	if(get_mac() < 0)
		return -1;

	loop = ev_default_loop(0);
	ev_io_init(&netio, netfd_read_cb, netfd, EV_READ);
	ev_io_start(loop, &netio);
	ev_io_init(&tapio, tapfd_read_cb, tapfd, EV_READ);
	ev_io_start(loop, &tapio);
	ev_signal_init(&term, term_cb, SIGTERM|SIGQUIT);
	ev_signal_start(loop, &term);

	if(do_gssinit(loop, NULL) < 0) {
		close(tapfd);
		close(netfd);
		return -1;
	}

	ev_init(&init_retry, init_retry_cb);
	last_init_activity = ev_now(loop);
	init_retry_cb(loop, &init_retry, EV_TIMER);

	ev_run(loop, 0);
	if(netinit_util) {
		pid_t pid;
		netinit_args[2] = "shutdown";
		pid = fork();
		if(pid == 0) {
			close(tapfd);
			close(netfd);
			if(execv(netinit_util, netinit_args) < 0)
				exit(errno);
		}
	}

	close(tapfd);
	close(netfd);
	if(context != GSS_C_NO_CONTEXT)
		gss_delete_sec_context(&min, &context, NULL);
	return 0;
}

