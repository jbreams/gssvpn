#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <stdio.h>
#include <poll.h>
#include <gssapi/gssapi.h>
#include <unistd.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <syslog.h>

#define SERVICE_NAME "gssvpn"
#define STDIN 0
#define STDOUT 1

static int verbose = 0;

void gss_disp_loop(OM_uint32 status, OM_uint32 type) {
	gss_buffer_desc status_string = { 0, 0 };
	OM_uint32 context = 0, lmin, lmaj;

	do {
		lmaj = gss_display_status(&lmin, status, type, GSS_C_NO_OID,
						&context, &status_string);
		if(lmaj != GSS_S_COMPLETE)
			return;

		if(status_string.value) {
			syslog(LOG_ERR, "GSSAPI error %d: %.*s", status,
							status_string.length, status_string.value);
			gss_release_buffer(&lmin, &status_string);
		}
	} while(context != 0);
}

void display_gss_err(OM_uint32 major, OM_uint32 minor) {
	gss_disp_loop(major, GSS_C_GSS_CODE);
	gss_disp_loop(minor, GSS_C_MECH_CODE);
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
		syslog(LOG_DEBUG, "Acquired credentials for SERVICE_NAME");
	return 0;
}

int readremote(gss_buffer_desc * buffer) {
	buffer->length = 0;
	size_t r = read(STDIN, (void*)&buffer->length, sizeof(OM_uint32));
	if(r < sizeof(OM_uint32))
		return errno;

	buffer->length = ntohl(buffer->length);
	buffer->value = malloc(buffer->length + 1);
	r = 0;
	do {
		size_t n = read(STDIN, buffer->value + r,
						buffer->length - r);
		if(n < 1) {
			n = errno;
			syslog(LOG_ERR, "Received less than expected from remote host: %d < %d: %s",
							r, buffer->length, strerror(n));
			return n;
		}
		r += n;
	} while(r < buffer->length);
	else if(verbose)
		syslog(LOG_DEBUG, "Read %d bytes from remote host", r);
	return 0;
}

int writeremote(gss_buffer_desc * buffer) {
	OM_uint32 length = htonl(buffer->length), min;
	size_t s = write(STDOUT, (void*)&length, sizeof(OM_uint32));
	if(s < sizeof(OM_uint32))
		return errno;

	s = write(STDOUT, buffer->value, buffer->length);
	gss_release_buffer(&min, buffer);
	if(s < buffer->length)
		return errno;
	if(verbose)
		syslog(LOG_DEBUG, "Wrote %d bytes to remote host", s);
	return 0;
}

int main(int argc, char ** argv) {
	gss_cred_id_t server_creds;
	int rc, tapfd, confstate;
	OM_uint32 maj, min, ret_flags;
	gss_buffer_desc remotein, remoteout;
	gss_name_t client;
	gss_OID doid;
	gss_ctx_id_t context = GSS_C_NO_CONTEXT;
	struct ifreq ifr;
	struct pollfd pfds[2];

	openlog("gssvpnd", 0, LOG_DAEMON);

	remotein.length = 0;
	remoteout.length = 0;
	for(rc = 0; rc < argc; rc++) {
		if(strcmp(argv[rc], "--verbose") == 0)
			verbose = 1;
	}

	rc = get_server_creds(&server_creds);
	if(rc != 0)
		return -1;

	do {
		OM_uint32 lmin;
		rc = readremote(&remotein);
		if(rc != 0) {
			syslog(LOG_ERR, "Error receiving packet during init: %s",
							strerror(rc));
			return -1;
		}

		if(verbose)
			syslog(LOG_DEBUG, "Accepting security context.");
		maj = gss_accept_sec_context(&min, &context, server_creds,
						&remotein, GSS_C_NO_CHANNEL_BINDINGS, &client,
						&doid, &remoteout, &ret_flags, NULL, NULL);
		gss_release_buffer(&lmin, &remotein);
		if(remoteout.length > 0) {
			OM_uint32 lmin;
			rc = writeremote(&remoteout);
			gss_release_buffer(&lmin, &remoteout);
		}

		if(maj != GSS_S_COMPLETE && maj != GSS_S_CONTINUE_NEEDED) {
			if(context != GSS_C_NO_CONTEXT)
				gss_delete_sec_context(&lmin, &context, GSS_C_NO_BUFFER);
			syslog(LOG_ERR, "Error initializing security context");
			display_gss_err(maj, min);
			return -1;
		}
	} while(maj == GSS_S_CONTINUE_NEEDED);

	tapfd = open("/dev/net/tun", O_RDWR);

	if(tapfd < 0) {
		tapfd = errno;
		syslog(LOG_ERR, "Error opening TAP device: %s",
						strerror(tapfd));
		gss_delete_sec_context(&min, &context, GSS_C_NO_BUFFER);
		gss_release_cred(&min, &server_creds);
		return -1;
	} else if(verbose)
		syslog(LOG_DEBUG, "Opened tun/tap device to fd %d", tapfd);

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
	rc = ioctl(tapfd, TUNSETIFF, (void*)&ifr);
	if(rc < 0) {
		rc = errno;
		syslog(LOG_ERR, "Error setting up TAP device: %s",
						strerror(rc));
		close(tapfd);
		gss_delete_sec_context(&min, &context, GSS_C_NO_BUFFER);
		gss_release_cred(&min, &server_creds);
		return -1;
	} else if(verbose)
		syslog(LOG_DEBUG, "Set up tun/tap device %s", ifr.ifr_ifrn.ifrn_name);
	
	if(tapfd < 0) {
		rc = errno;
		syslog(LOG_ERR, "Error setting up TAP device: %s",
						strerror(rc));
		gss_delete_sec_context(&min, &context, GSS_C_NO_BUFFER);
		gss_release_cred(&min, &server_creds);
		return -1;
	}

	int ts = socket(PF_UNIX, SOCK_STREAM, 0);
	ioctl(ts, SIOCGIFFLAGS, &ifr);
	ifr.ifr_flags |= IFF_UP;
	ioctl(ts, SIOCSIFFLAGS, &ifr);
	close(ts);

	pfds[0].fd = 0;
	pfds[0].events = POLLIN;
	pfds[1].fd = tapfd;
	pfds[1].events = POLLIN;

	if(verbose)
		syslog(LOG_DEBUG, "Negotiating MTU.");
	

	if(verbose)
		syslog(LOG_DEBUG, "Starting listener loop.");
	while(rc = poll(pfds, 2, -1)) {
		if(pfds[0].revents == POLLIN) {
			rc = readremote(&remotein);
			gss_buffer_desc plaintext;
			if(rc != 0) {
				syslog(LOG_ERR, "Error reading from remote host: %s",
								strerror(rc));
				break;
			}
			if(remotein.length == 0) {
				syslog(LOG_ERR, "Remote host has closed the connection.");
				break;
			}
			maj = gss_unwrap(&min, context, &remotein, &plaintext,
							&confstate, NULL);
			if(maj != GSS_S_COMPLETE) {
				syslog(LOG_ERR, "Error unwrapping packet from remote host");
				display_gss_err(maj, min);
				break;
			}

			write(tapfd, plaintext.value, plaintext.length);
			memset(plaintext.value, 0, plaintext.length);
			gss_release_buffer(&min, &plaintext);
			gss_release_buffer(&min, &remotein);
		}
		if(pfds[1].revents == POLLIN) {
			gss_buffer_desc plaintext;
			plaintext.value = malloc(1500);

			plaintext.length = read(tapfd, plaintext.value, 1500);
			if(plaintext.length < 0) {
				rc = errno;
				syslog(LOG_ERR, "Error receiving packet from ethernet bridge: %s",
								strerror(rc));
				break;
			}
			
			maj = gss_wrap(&min, context, 1, GSS_C_QOP_DEFAULT, &plaintext, 
							&confstate, &remoteout);
			if(maj != GSS_S_COMPLETE) {
				syslog(LOG_ERR, "Error wrapping packet for remote host.");
				display_gss_err(maj, min);
				break;
			}
			rc = writeremote(&remoteout);
			memset(plaintext.value, 0, 1500);
			free(plaintext.value);
		}
	}

	close(tapfd);
	gss_delete_sec_context(&min, &context, GSS_C_NO_BUFFER);
	gss_release_cred(&min, &server_creds);
	return 0;
}
