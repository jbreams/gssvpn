
#define PAC_DATA 0
#define PAC_GSSINIT 2
#define PAC_NETINIT 1
#define PAC_SHUTDOWN 3
#define PAC_NOOP 4

#define CLIENT_IP 1
#define CLIENT_ETHERNET 2
#define CLIENT_ALL 3

#define PBUFF_SIZE 3000

struct pbuff {
	struct conn * parent;
	struct pbuff * next;
	char hash;
	unsigned int len;
	unsigned int have;
	unsigned int seq;
	char buff[PBUFF_SIZE];
};

struct conn {
	gss_ctx_id_t context;
	OM_uint32 gssstate;
	sockaddr_in addr;
	unsigned int seq;
	int bs;
	unsigned char mac[6];
	time_t touched;
	struct pbuff * packets[255];
	struct conn * ipnext;
	struct conn * ethernext;
};

void display_gss_err(OM_uint32 major, OM_uint32 minor);
int send_packet(int s, gss_buffer_desc * out,
			struct sockaddr_in * peer, int bs, char pac) 
int recv_packet(int s, gss_buffer_desc * out, char * pacout,
			struct sockaddr_in * peer);
void log(int level, char * fmt, ...);
OM_uint16 get_seq(struct sockaddr_in * peer);
void free_packet(struct pbuff * buff);
struct pbuff * get_packet(struct sockaddr_in * addr, OM_uint32 seq, 
			OM_uint32 len, int * bs);
char hash(char * in, int len);

#ifdef GSSVPN_SERVER
struct conn * get_conn(struct sockaddr_in * peer);
struct conn * get_conn_ether(char * mac);
void unlink_conn(struct conn * conn, char which);
#endif
struct pbuff * get_packet(struct sockaddr_in * addr, OM_uint16 seq, 
			OM_uint16 len, int * bs);
void free_packet(struct pbuff * buff);
OM_uint32 get_seq(struct sockaddr_in * peer);
