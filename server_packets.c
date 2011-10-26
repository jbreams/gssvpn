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
#include <sys/socket.h>
#include <stdio.h>
#include <gssapi/gssapi.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "libev/ev.h"
#define GSSVPN_SERVER
#include "gssvpn.h"

extern struct conn * clients_ip[255];
extern struct conn * clients_ether[255];
extern int verbose;
uint8_t sid_counter = 1;

struct conn * get_conn(struct sockaddr_in * peer, uint16_t sid) {
	struct conn * client;
	struct sockaddr * addr = (struct sockaddr*)peer;
	uint8_t h = sid ? sid & 0xff : hash((uint8_t*)addr->sa_data, 6);

	client = clients_ip[h];
	while(client && client->sid != sid)
		client = client->ipnext;
	if(client)
		return client;

	client = malloc(sizeof(struct conn));
	if(client == NULL) {
		logit(1, "Unable to allocate new connection for client");
		return NULL;
	}
	memset(client, 0, sizeof(struct conn));
	client->ipnext = clients_ip[h];
	clients_ip[h] = client;
	client->sid = ((uint16_t)sid_counter++) << 8;
	client->sid |= h;

	client->context = GSS_C_NO_CONTEXT;
	client->gssstate = GSS_S_CONTINUE_NEEDED;
	return client;
}

gss_ctx_id_t get_context(struct sockaddr_in * peer, uint16_t sid) {
	struct conn * client = get_conn(peer, sid);
	if(!client)
		return NULL;
	if(client->gssstate != GSS_S_COMPLETE)
		return NULL;
	return client->context;
}

void unlink_conn(struct conn * conn, char which) {
	uint8_t h;
	struct conn * last = NULL;
	if(which & CLIENT_IP) {
		struct sockaddr * addr = (struct sockaddr*)&conn->addr;
		h = hash((uint8_t*)addr->sa_data, 6);
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

