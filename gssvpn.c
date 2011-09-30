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
#include <netinet/tcp.h>
#if defined(HAVE_IF_TUN)
#include <linux/if_tun.h>
#endif
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <syslog.h>

#define SERVICE_NAME "gssvpn"

static int verbose=0;

void gss_disp_loop(OM_uint32 status, OM_uint32 type) {
	gss_buffer_desc status_string = { 0, 0 };
	OM_uint32 context = 0, lmin, lmaj;

	do {
		lmaj = gss_display_status(&lmin, status, type, GSS_C_NO_OID,
						&context, &status_string);
		if(lmaj != GSS_S_COMPLETE)
			return;

		if(status_string.value) {
			fprintf(stderr, "GSSAPI error %d: %.*s\n", status,
							status_string.length, status_string.value);
			gss_release_buffer(&lmin, &status_string);
		}
	} while(context != 0);
}

void display_gss_err(OM_uint32 major, OM_uint32 minor) {
	gss_disp_loop(major, GSS_C_GSS_CODE);
	gss_disp_loop(minor, GSS_C_MECH_CODE);
}

int connectto(char * host, int port, char * service) {
	struct hostent * hp;
	struct servent * sv;
	struct sockaddr_in remote_saddr;
	int s, flag = 1;

	if(service && !port) {
		sv = getservbyname(service, "tcp");

		if(sv == NULL) {
			fprintf(stderr, "Error looking up service name for %s: %s\n",
					SERVICE_NAME, strerror(errno));
			return -1;
		}
	}

	hp = gethostbyname(host);
	if(hp == NULL) {
		fprintf(stderr, "Error looking up %s: %s\n", host, strerror(errno));
		return -1;
	}

	remote_saddr.sin_family = hp->h_addrtype;
	memcpy(&remote_saddr.sin_addr, hp->h_addr, sizeof(remote_saddr.sin_addr));
	if(port)
		remote_saddr.sin_port = htons(port);
	else if(sv)
		remote_saddr.sin_port = sv->s_port;

	s = socket(AF_INET, SOCK_STREAM, 0);
	if(s < 0) {
		fprintf(stderr, "Error creating socket: %s\n", strerror(errno));
		return -1;
	}
	if(connect(s, (struct sockaddr*)&remote_saddr, sizeof(remote_saddr)) < 0) {
		fprintf(stderr, "Error connecting to %s:%d: %s\n", host, 
			sv->s_port, strerror(errno));
		close(s);
		return -1;
	}
	
	setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(int));
	return s;
}

int readremote(gss_buffer_desc * buffer, int socket) {
	buffer->length = 0;
	size_t r;
	r = recv(socket, (void*)&buffer->length, sizeof(OM_uint32), 0);
	if(r < sizeof(OM_uint32) || buffer->length == 0) {
		return errno;
	}

	buffer->length = ntohl(buffer->length);
	buffer->value = malloc(buffer->length + 1);
	r = 0;

	do {
		size_t n;
		n = recv(socket, buffer->value + r,
						buffer->length - r, 0);
		if(n < 1) {
			n = errno;
			fprintf(stderr, "Received data is less than expected: %d < %d\n",
							r, buffer->length);
			free(buffer->value);
			return n;
		}
		r += n;
	} while(r < buffer->length);

	if(verbose)
		fprintf(stderr, "Read %d bytes from remote host\n", r);
	return 0;
}

int writeremote(gss_buffer_desc * buffer, int socket) {
	OM_uint32 length = htonl(buffer->length), min;
	size_t s = send(socket, (void*)&length, sizeof(OM_uint32), 0);
	if(s < sizeof(OM_uint32))
		return errno;
	
	s = send(socket, buffer->value, buffer->length, 0);
	gss_release_buffer(&min, buffer);
	if(s < buffer->length)
		return errno;
	if(verbose)
		fprintf(stderr, "Wrote %d bytes to remote host\n", s);
	return 0;
}

int main(int argc, char ** argv) {
	gss_ctx_id_t context = GSS_C_NO_CONTEXT;
	OM_uint32 maj, min;
	gss_buffer_desc sendbuf, recvbuf = GSS_C_EMPTY_BUFFER;
	gss_name_t target_name;
	gss_OID_set_desc mechs;
	struct ifreq ifr;
	int ch, sfd, tapfd, rc, port = 0;
	char * hostname = NULL, * service = strdup(SERVICE_NAME);

	while((ch = getopt(argc, argv, "vh:p:s:")) != -1) {
		switch(ch) {
			case 'v':
				verbose=1;
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
		}
	}
	
	if(hostname == NULL) {
		fprintf(stderr, "Must supply hostname to connect to.\n");
		return -EINVAL;
	}
	memset(&mechs, 0, sizeof(mechs));
	char * prodid = malloc(strlen(service) + strlen(hostname) + 2);

	sprintf(prodid, "%s@%s", service, hostname);
	sendbuf.value = prodid;
	sendbuf.length = strlen(prodid);

	maj = gss_import_name(&min, &sendbuf,
		(gss_OID) GSS_C_NT_HOSTBASED_SERVICE, &target_name);
	free(prodid);

	sfd = connectto(hostname, port, service);
	free(hostname);
	free(service);
	if(sfd < 0)
		return -1;

	do {
		OM_uint32 lmin;
		maj = gss_init_sec_context(&min,
			GSS_C_NO_CREDENTIAL, &context, target_name, NULL,
			0, 0, NULL, &recvbuf, NULL, &sendbuf, NULL, NULL);
		
		if(maj != GSS_S_COMPLETE && maj != GSS_S_CONTINUE_NEEDED) {
			if(context != GSS_C_NO_CONTEXT)
				gss_delete_sec_context(&lmin, &context, GSS_C_NO_BUFFER);
			display_gss_err(maj, min);
			return -1;
		}

		rc = writeremote(&sendbuf, sfd);
		if(rc != 0) {
			fprintf(stderr, "Error sending token: %s\n", strerror(rc));
			return -1;
		}

		if(maj == GSS_S_CONTINUE_NEEDED) {
			rc = readremote(&recvbuf, sfd);
			if(rc != 0) {
				fprintf(stderr, "Error receiving token: %s\n", strerror(rc));
				return -1;
			}
		}
	} while(maj == GSS_S_CONTINUE_NEEDED);

	tapfd = open("/dev/tap0", O_RDWR);
	if(tapfd < 0) {
		fprintf(stderr, "Error opening TAP device: %s\n", strerror(errno));
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "tap0");
	int ts = socket(PF_UNIX, SOCK_STREAM, 0);
	ioctl(ts, SIOCGIFFLAGS, &ifr);
	ifr.ifr_flags |= IFF_UP;
	ioctl(ts, SIOCSIFFLAGS, &ifr);
	close(ts);

	while(1) {
		fd_set rdset;

		FD_ZERO(&rdset);
		FD_SET(tapfd, &rdset);
		FD_SET(sfd, &rdset);
		rc = select(tapfd + 1, &rdset, NULL, NULL, NULL);
		if(rc < 0)
			break;

		if(FD_ISSET(sfd, &rdset)) {
			rc = readremote(&recvbuf, sfd);
			gss_buffer_desc plaintext;
			if(rc != 0) {
				fprintf(stderr, "Error reading from remote host: %s\n",
								strerror(rc));
				break;
			}

			if(recvbuf.length == 0) {
				fprintf(stderr, "Remote host has closed the connection.\n");
				break;
			}

			maj = gss_unwrap(&min, context, &recvbuf, &plaintext, NULL, NULL);
			if(maj != GSS_S_COMPLETE) {
				display_gss_err(maj, min);
				break;
			}

			if(verbose)
				fprintf(stderr, "Writing %d bytes to local network\n",
								plaintext.length);
			write(tapfd, plaintext.value, plaintext.length);
			memset(plaintext.value, 0, plaintext.length);
			gss_release_buffer(&min, &plaintext);
			gss_release_buffer(&min, &recvbuf);
		}
		if(FD_ISSET(tapfd, &rdset)) {
			gss_buffer_desc plaintext;
			plaintext.value = malloc(1500);
			plaintext.length = read(tapfd, plaintext.value, 1500);

			if(verbose)
				fprintf(stderr, "Received %d bytes from local network\n",
								plaintext.length);

			if(plaintext.length < 0) {
				fprintf(stderr, "Error receiving packet from ethernet bridge: %s\n",
								strerror(errno));
				break;
			}

			maj = gss_wrap(&min, context, 1, GSS_C_QOP_DEFAULT, &plaintext,
							NULL, &sendbuf);
			if(maj != GSS_S_COMPLETE) {
				display_gss_err(maj, min);
				break;
			}
			rc = writeremote(&sendbuf, sfd);
			memset(plaintext.value, 0, 1500);
			free(plaintext.value);
		}
	}

	close(sfd);
	close(tapfd);
	gss_delete_sec_context(&min, &context, GSS_C_NO_BUFFER);
	return 0;
}
