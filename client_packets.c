#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <gssapi/gssapi.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <netinet/in.h>
#include "gssvpn.h"

struct pbuff * packets[255];
uint16_t seq = 0;

struct pbuff * get_packet(struct sockaddr_in * addr,
	uint16_t seq, uint16_t len, int *bs) {
	uint16_t hb[2];
	uint8_t h;
	struct pbuff * p;
	hb[0] = seq;
	hb[1] = len;

	h = hash((char*)hb, sizeof(hb));
	p = packets[h];
	while(p && p->seq != seq && p->len != len)
		p = p->next;
	if(p)
		return p;

	p = malloc(sizeof(struct pbuff));
	if(!p) {
		logit(1, "Could not allocate a packet, out of memory.");
		return NULL;
	}
	memset(p, 0, sizeof(struct pbuff));
	p->next = packets[h];
	packets[h] = p;
	p->hash = h;
	p->len = len;
	p->seq = seq;
	
	return p;
}

void free_packet(struct pbuff * buff) {
	uint8_t h = buff->hash;
	struct pbuff * last = NULL, *cur = packets[h];
	while(cur && cur != buff) {
		last = cur;
		cur = cur->next;
	}

	if(!cur) {
		logit(1, "Trying to free orphaned packet.");
		return;
	}

	if(last)
		last->next = cur->next;
	else
		packets[h] = cur->next;
	free(buff);
}

uint16_t get_seq(struct sockaddr_in * peer) {
	return ++seq;
}

