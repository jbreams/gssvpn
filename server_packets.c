#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <gssapi/gssapi.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <netinet/in.h>
#define GSSVPN_SERVER
#include "gssvpn.h"

extern struct conn ** clients_ip;
extern struct conn ** clients_ether;
extern int verbose;

struct conn * get_conn(struct sockaddr_in * peer) {
	char * peerstr = (char*)peer;
	struct conn * client;
	int i;
	char h = hash((char*)peer, sizeof(struct sockaddr_in));

	client = clients_ip[h];
	while(client && memcmp(&client->addr, peer,
			sizeof(struct sockaddr_in)) != 0)
		client = client->ipnext;
	if(client)
		return client;

	client = malloc(sizeof(struct conn));
	if(client == NULL) {
		log(1, "Unable to allocate new connection for client");
		return NULL;
	}
	client->ipnext = clients_ip[h];
	clients_ip[h] = client;

	memset(client, 0, sizeof(struct conn));
	memcpy(&client->addr, peer, sizeof(struct sockaddr_in));
	client->gssstate = GSS_S_CONTINUE_NEEDED;
	client->context = GSS_C_NO_CONTEXT;
	client->bs = -1;
	client->touched = time(NULL);
	return client;
}

struct conn * get_conn_ether(char * mac) {
	char h = hash(mac, 6);
	struct conn * client = clients_ether[h];
	while(client && memcmp(client->mac, mac, 6) != 0)
		client = client->ethernext;
	return client;
}

void unlink_conn(struct conn * conn, char which) {
	char h;
	struct conn * last = NULL;
	if(which & CLIENT_IP) {
		h = hash((char*)&conn->addr, sizeof(struct sockaddr_in));
		struct conn * cur = clients_ip[h];
		while(cur && cur != conn) {
			last = cur;
			cur = cur->ipnext;
		}
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
		if(last)
			last->ethernext = conn->ethernext;
		else
			clients_ether[h] = conn->ethernext;
	}
}

struct pbuff * get_packet(struct sockaddr_in * addr, uint16_t seq, 
			uint16_t len, int * bs) {
	struct conn * conn = get_conn(addr);
	struct pbuff * packet = NULL;
	char hbuf[20], i;
	if(!conn)
		return NULL;

	memcpy(hbuf, &seq, sizeof(seq));
	memcpy(hbuf + sizeof(seq), &len, sizeof(len));
	i = hash(hbuf, 4);
	
	packet = conn->packets[i];
	while(packet && !(packet->seq == seq && packet->len == len))
		packet = packet->next;

	if(packet)
		return packet;

	packet = malloc(sizeof(struct pbuff));
	if(!packet) {
		log(1, "Error allocating a packet buffer");
		return NULL;
	}
	packet->len = len;
	packet->seq = seq;
	packet->have = 0;
	packet->parent = conn;
	packet->next = conn->packets[i];
	packet->hash = i;
	conn->packets[i] = packet;

	return packet;
}

void free_packet(struct pbuff * buff) {
	char hbuf[20], i;
	memcpy(hbuf, &buff->seq, sizeof(buff->seq));
	memcpy(hbuf + sizeof(buff->seq), &buff->len, sizeof(buff->len));
	i = hash(hbuf, sizeof(hbuf));
	
	struct conn * client = buff->parent;
	struct pbuff * last = NULL;
	struct pbuff * cur = client->packets[i];
	while(cur && cur != buff) {
		last = cur;
		cur = cur->next;
	}

	if(!cur) {
		log(1, "Trying to free an orphaned packet from conn pool %p", buff);
		return;
	}
	
	if(last)
		last->next = cur->next;
	else
		client->packets[cur->hash] = cur->next;

	free(buff);
}

uint16_t get_seq(struct sockaddr_in * peer) {
	struct conn * client = get_conn(peer);
	if(client)
		return ++client->seq;
	return 0;
}

