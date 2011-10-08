
#define PAC_DATA 0
#define PAC_GSSINIT 2
#define PAC_NETINIT 1
#define PAC_SHUTDOWN 3
#define PAC_NOOP 4

#define CLIENT_IP 1
#define CLIENT_ETHERNET 2
#define CLIENT_ALL 3

#ifdef GSSVPN_SERVER
struct conn {
	gss_ctx_id_t context;
	unsigned long gssstate;
	struct sockaddr_in addr;
	char ipstr[20];
	unsigned char mac[6];
	time_t touched;
	struct conn * ipnext;
	struct conn * ethernext;
};
#endif

void display_gss_err(OM_uint32 major, OM_uint32 minor);
int send_packet(int s, gss_buffer_desc * out,
			struct sockaddr_in * peer, char pac); 
int recv_packet(int s, gss_buffer_desc * out,
			char * pacout, struct sockaddr_in * peer);
void logit(int level, char * fmt, ...);
char hash(char * in, int len);
int open_tap(char * dev);
int open_net(short port);
gss_ctx_id_t get_context(struct sockaddr_in * peer);

#ifdef GSSVPN_SERVER
struct conn * get_conn(struct sockaddr_in * peer);
struct conn * get_conn_ether(char * mac);
void unlink_conn(struct conn * conn, char which);
#endif

