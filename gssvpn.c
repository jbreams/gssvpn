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
#include <net/if_dl.h>
#if defined(HAVE_IF_TUN)
#include <linux/if_tun.h>
#endif
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <ifaddrs.h>
#include <ev.h>
#include "gssvpn.h"

gss_ctx_id_t context = GSS_C_NO_CONTEXT;
OM_uint32 gssstate = GSS_S_CONTINUE_NEEDED;
int tapfd, netfd, gbs = PBUFF_SIZE + 6, reap = 30, verbose = 0;
struct sockaddr_in server;
char * tapdev, *service, *hostname;
extern struct pbuff * packets[255];

int do_netinit() {
	struct ifaddrs * ifp, *cifp;
	char mac[6];
	OM_uint32 maj, min, confstate;
	gss_buffer_desc crypted = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc plaintext = { sizeof(mac), mac };
	int rc;

	if(getifaddrs(&ifp) < 0) {
		logit(1, "Error getting list of interfaces %m.");
		return -1;
	}
	
	for(cifp = ifp; cifp && strcmp(cifp->ifa_name, tapdev) != 0;
					cifp = cifp->ifa_next);
	if(!cifp) {
		logit(1, "Couldn't find %s in list of interfaces", tapdev);
		freeifaddrs(ifp);
		return -1;
	}

	struct sockaddr_dl* sdl = (struct sockaddr_dl*)cifp->ifa_addr;
	memcpy(mac, LLADDR(sdl), sizeof(mac));
	freeifaddrs(ifp);

	maj = gss_wrap(&min, context, 1, GSS_C_QOP_DEFAULT, &plaintext,
					&confstate, &crypted);
	if(maj != GSS_S_COMPLETE) {
		logit(1, "Error while wrapping netinit response");
		display_gss_err(maj, min);
	}

	rc = send_packet(netfd, &crypted, &server, PAC_NETINIT);
	gss_release_buffer(&min, &crypted);
	return rc;
}

int do_gssinit(gss_buffer_desc * in) {
	gss_name_t target_name;
	char prodid[255];
	gss_buffer_desc tokenout = { 255, &prodid };
	OM_uint32 min;

	tokenout.length = snprintf(prodid, 255, "%s@%s", service, hostname);
	gssstate = gss_import_name(&min, &tokenout, 
					(gss_OID)GSS_C_NT_HOSTBASED_SERVICE,
					&target_name);
	tokenout.value = NULL;
	tokenout.length = 0;

	if(context == GSS_C_NO_CONTEXT)
		gss_delete_sec_context(&min, &context, NULL);
	gssstate = gss_init_sec_context(&min, GSS_C_NO_CREDENTIAL,
					&context, target_name, NULL, 0, 0, NULL,
					in, NULL, &tokenout, NULL, NULL);

	if(gssstate != GSS_S_COMPLETE && gssstate != GSS_S_CONTINUE_NEEDED) {
		if(context != GSS_C_NO_CONTEXT)
			gss_delete_sec_context(&min, &context, GSS_C_NO_BUFFER);
		display_gss_err(gssstate, min);
		return -1;
	}

	gss_release_name(&min, &target_name);

	if(tokenout.length) {
		int rc;
		rc = send_packet(netfd, &tokenout, &server, PAC_GSSINIT);
		gss_release_buffer(&min, &tokenout);
		if(rc < 0)
			return -1;
	}
	return 0;
}

void netfd_read_cb(struct ev_loop * loop, ev_io * ios, int revents) {
	gss_buffer_desc crypted = GSS_C_EMPTY_BUFFER;
	OM_uint32 maj, min;
	int rc;
	uint8_t pac;
	struct sockaddr_in peer;

	rc = recv_packet(netfd, &crypted, &pac, &peer);
	if(rc != 0)
		return;
	
	if(pac == PAC_DATA) {
		gss_buffer_desc plaintext = GSS_C_EMPTY_BUFFER;
		maj = gss_unwrap(&min, context, &crypted, &plaintext, NULL, NULL);
		gss_release_buffer(&min, &crypted);
		if(maj != GSS_S_COMPLETE) {
			logit(1, "Error unwrapping packet.");
			display_gss_err(maj, min);
			return;
		}
		if(verbose)
			logit(0, "Writing %d bytes to TAP", plaintext.length);

		write(tapfd, plaintext.value, plaintext.length);
		gss_release_buffer(&min, &plaintext);
		return;
	}
	else if(pac == PAC_NETINIT) {
		do_netinit();
	}
	else if(pac == PAC_GSSINIT)
		do_gssinit(&crypted);
	else if(pac == PAC_SHUTDOWN)
		ev_break(loop, EVBREAK_ALL);
	if(crypted.length)
		gss_release_buffer(&min, &crypted);
}

void tapfd_read_cb(struct ev_loop * loop, ev_io * ios, int revents) {
	char inbuff[PBUFF_SIZE];
	gss_buffer_desc plaintext = { PBUFF_SIZE, inbuff };
	gss_buffer_desc crypted;
	OM_uint32 maj, min;

	plaintext.length = read(tapfd, inbuff, PBUFF_SIZE);
	if(plaintext.length < 0) {
		logit(1, "Error receiving packet from TAP: %s",
					strerror(errno));
		return;
	}
	else if(verbose)
		logit(-1, "Received packet from TAP of %d bytes", plaintext.length);

	maj = gss_wrap(&min, context, 1, GSS_C_QOP_DEFAULT, &plaintext,
					NULL, &crypted);
	if(maj != GSS_S_COMPLETE) {
		logit(1, "Error wrapping packet.");
		display_gss_err(maj, min);
		return;
	}

	send_packet(netfd, &crypted, &server, PAC_DATA);
	gss_release_buffer(&min, &crypted);
	return;
}

int main(int argc, char ** argv) {
	ev_io tapio, netio;
	struct ev_loop * loop;
	char ch;
	short port = 0;
	struct hostent * hostinfo;
	OM_uint32 min;

	memset(&server, 0, sizeof(struct sockaddr_in));
	
	while((ch = getopt(argc, argv, "vh:p:s:d:")) != -1) {
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
			case 'd':
				tapdev = strdup(optarg);
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

	tapfd = open_tap(tapdev);
	if(tapfd < 0)
		return -1;

	loop = ev_default_loop(0);
	ev_io_init(&netio, netfd_read_cb, netfd, EV_READ);
	ev_io_start(loop, &netio);
	ev_io_init(&tapio, tapfd_read_cb, tapfd, EV_READ);
	ev_io_start(loop, &tapio);

	if(do_gssinit(NULL) < 0) {
		close(tapfd);
		close(netfd);
		return -1;
	}

	ev_run(loop, 0);

	close(tapfd);
	close(netfd);
	if(context == GSS_C_NO_CONTEXT)
		gss_delete_sec_context(&min, &context, NULL);

	return 0;
}
