#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <gssapi/gssapi.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#define GSSVPN_SERVER
#include "gssvpn.h"

extern struct conn * clients_ip[255];
extern struct conn * clients_ether[255];
extern int verbose;

struct conn * get_conn(struct sockaddr_in * peer) {
	char * peerstr = (char*)peer;
	char * ipstr; 
	struct conn * client;
	int i;
	uint8_t h = hash((char*)peer, sizeof(struct sockaddr_in));

	client = clients_ip[h];
	while(client && memcmp(&client->addr, peer,
			sizeof(struct sockaddr_in)) != 0)
		client = client->ipnext;
	if(client)
		return client;

	client = malloc(sizeof(struct conn));
	if(client == NULL) {
		logit(1, "Unable to allocate new connection for client");
		return NULL;
	}
	client->ipnext = clients_ip[h];
	clients_ip[h] = client;

	memset(client, 0, sizeof(struct conn));
	memcpy(&client->addr, peer, sizeof(struct sockaddr_in));
	ipstr = inet_ntoa(peer->sin_addr);
	strcpy(client->ipstr, ipstr);
	client->gssstate = GSS_S_CONTINUE_NEEDED;
	client->context = GSS_C_NO_CONTEXT;
	client->touched = time(NULL);
	return client;
}

void unlink_conn(struct conn * conn, char which) {
	uint8_t h;
	struct conn * last = NULL;
	if(which & CLIENT_IP) {
		h = hash((char*)&conn->addr, sizeof(struct sockaddr_in));
		struct conn * cur = clients_ip[h];
		while(cur && cur != conn) {
			last = cur;
			cur = cur->ipnext;
		}
		if(!cur)
			return;
		if(last)
			last->ipnext = conn->ipnext;
		else
			clients_ip[h] = conn->ipnext;
	}
	if(which & CLIENT_ETHERNET) {
		h = hash(conn->mac, 6);
		struct conn * cur = clients_ether[h];
		while(cur && cur != conn) {
			last = cur;
			cur = cur->ipnext;
		}
		if(!cur)
			return;
		if(last)
			last->ethernext = conn->ethernext;
		else
			clients_ether[h] = conn->ethernext;
	}
}

