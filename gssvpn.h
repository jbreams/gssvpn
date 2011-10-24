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

#define PAC_DATA 0
#define PAC_GSSINIT 2
#define PAC_NETINIT 1
#define PAC_SHUTDOWN 3
#define PAC_ECHO 4

#define CLIENT_IP 1
#define CLIENT_ETHERNET 2
#define CLIENT_ALL 3

#ifdef GSSVPN_SERVER
struct conn {
	uint16_t sid;
	gss_ctx_id_t context;
	unsigned long gssstate;
	struct sockaddr_in addr;
	char ipstr[20];
	char * princname;
	unsigned char mac[6];
	struct conn * ipnext;
	struct conn * ethernext;
	ev_child nichild;
	ev_io nipipe;
	ev_timer conntimeout;
	gss_buffer_desc ni;	
	struct ev_loop * loop;
};
#endif

void display_gss_err(OM_uint32 major, OM_uint32 minor);
int send_packet(int s, gss_buffer_desc * out,
			struct sockaddr_in * peer, char pac, uint16_t sid); 
int recv_packet(int s, gss_buffer_desc * out,
			char * pacout, struct sockaddr_in * peer, uint16_t * sid);
void logit(int level, char * fmt, ...);
char hash(char * in, int len);
int open_tap(char * dev);
int open_net(short port);
gss_ctx_id_t get_context(struct sockaddr_in * peer, uint16_t sid);

#ifdef GSSVPN_SERVER
struct conn * get_conn(struct sockaddr_in * peer, uint16_t sid);
struct conn * get_conn_ether(char * mac);
void unlink_conn(struct conn * conn, char which);
#endif

