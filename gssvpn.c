#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h>
#include <stdio.h>
#include <poll.h>
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

#define SERVICE_NAME "gssvpn"
#define HOST_NAME "localhost"

static int verbose=1;

int connectto(char * host) {
	struct sockaddr_in saddr;
	struct hostent * hp;
	struct servent * sv = getservbyname(SERVICE_NAME, "tcp");
	int s;

	if(sv == NULL) {
		fprintf(stderr, "Error looking up service name for %s: %s\n",
						SERVICE_NAME, strerror(errno));
		return -1;
	}

	hp = gethostbyname(host);
	if(hp == NULL) {
		fprintf(stderr, "Error looking up %s: %s\n", host, strerror(errno));
		return -1;
	}

	saddr.sin_family = hp->h_addrtype;
    memcpy(&saddr.sin_addr, hp->h_addr, sizeof(saddr.sin_addr));
    saddr.sin_port = sv->s_port;

	s = socket(AF_INET, SOCK_STREAM, 0);
	if(s < 0) {
		fprintf(stderr, "Error creating socket: %s\n", strerror(errno));
		return -1;
	}
	if(connect(s, (struct sockaddr*)&saddr, sizeof(saddr)) < 0) {
		fprintf(stderr, "Error connecting to %s:%d: %s\n",
						host, sv->s_port, strerror(errno));
		close(s);
		return -1;
	}
	return s;
}

int readremote(gss_buffer_desc * buffer, int socket) {
	buffer->length = 0;
	size_t r = read(socket, (void*)&buffer->length, sizeof(OM_uint32));
	if(r < sizeof(OM_uint32))
		return errno;

	buffer->length = ntohl(buffer->length);
	if(verbose)
		fprintf(stderr, "Going to read %d bytes from remote host\n",
						buffer->length);
	buffer->value = malloc(buffer->length + 1);
	r = read(socket, buffer->value, buffer->length);
	if(r < buffer->length)
		return errno;
	else if(verbose)
		fprintf(stderr, "Read %d bytes from remote host\n", r);
	return 0;
}

int writeremote(gss_buffer_desc * buffer, int socket) {
	OM_uint32 length = htonl(buffer->length), min;
	fprintf(stderr, "Going to write %d bytes to remote host\n", length);
	size_t s = write(socket, (void*)&length, sizeof(OM_uint32));
	if(s < sizeof(OM_uint32))
		return errno;

	s = write(socket, buffer->value, buffer->length);
	gss_release_buffer(&min, buffer);
	if(s < buffer->length)
		return errno;
	fprintf(stderr, "Wrote %d bytes to remote host\n", s);
	return 0;
}

int main(int argc, char ** argv) {
	gss_ctx_id_t context = GSS_C_NO_CONTEXT;
	OM_uint32 maj, min;
	gss_buffer_desc sendbuf, recvbuf = GSS_C_EMPTY_BUFFER;
	gss_name_t target_name;
	gss_OID_set_desc mechs;
	struct pollfd pfds[2];
	struct ifreq ifr;

	memset(&mechs, 0, sizeof(mechs));
	char * prodid = malloc(sizeof(SERVICE_NAME) + sizeof(HOST_NAME) + 2);

	sprintf(prodid, "%s@%s", SERVICE_NAME, HOST_NAME);

	int sfd, tapfd, rc;

	sendbuf.value = prodid;
	sendbuf.length = strlen(prodid);

	maj = gss_import_name(&min, &sendbuf,
		(gss_OID) GSS_C_NT_HOSTBASED_SERVICE, &target_name);
	free(prodid);

	sfd = connectto(HOST_NAME);

	do {
		OM_uint32 lmin;
		maj = gss_init_sec_context(&min,
			GSS_C_NO_CREDENTIAL, &context, target_name, NULL,
			0, 0, NULL, &recvbuf, NULL, &sendbuf, NULL, NULL);
		
		if(maj != GSS_S_COMPLETE && maj != GSS_S_CONTINUE_NEEDED) {
			if(context != GSS_C_NO_CONTEXT)
				gss_delete_sec_context(&lmin, &context, GSS_C_NO_BUFFER);
			fprintf(stderr, "Error initializing security context %d:%d\n",
				maj, min);
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

	pfds[0].fd = sfd;
	pfds[0].events = POLLIN;
	pfds[1].fd = tapfd;
	pfds[1].events = POLLIN;

	while(poll(pfds, 2, -1)) {
		if(pfds[0].revents == POLLIN) {
			rc = readremote(&recvbuf, sfd);
			gss_buffer_desc plaintext;
			if(rc != 0) {
				fprintf(stderr, "Error reading from remote host: %s",
								strerror(rc));
				break;
			}

			if(recvbuf.length == 0) {
				fprintf(stderr, "Remote host has closed the connection.");
				break;
			}

			maj = gss_unwrap(&min, context, &recvbuf, &plaintext, NULL, NULL);
			if(maj != GSS_S_COMPLETE) {
				fprintf(stderr, "Error unwrapping packet from remote host: %d:%d",
								maj, min);
				break;
			}

			write(tapfd, plaintext.value, plaintext.length);
			memset(plaintext.value, 0, plaintext.length);
			gss_release_buffer(&min, &plaintext);
			gss_release_buffer(&min, &recvbuf);
		}
		if(pfds[1].revents == POLLIN) {
			gss_buffer_desc plaintext;
			plaintext.value = malloc(1500);
			plaintext.length = read(tapfd, plaintext.value, 1500);

			if(plaintext.length < 0) {
				fprintf(stderr, "Error receiving packet from ethernet bridge: %s",
								strerror(errno));
				break;
			}

			maj = gss_wrap(&min, context, 1, GSS_C_QOP_DEFAULT, &plaintext,
							NULL, &sendbuf);
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
