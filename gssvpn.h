
struct pbuff {
	unsigned long len;
	unsigned long have;
	unsigned long seq;
	char * buff;
	struct conn * conn;
};

struct conn {
	gss_ctx_id_t context;
	OM_uint32 gssstate;
	sockaddr_in addr;
	unsigned long seq;
	int bs;
	char mac[6];
	struct pbuff ** packets;
};

void display_gss_err(OM_uint32 major, OM_uint32 minor);
int send_packet(int s, gss_buffer_desc * out,
			struct sockaddr_in * peer, int bs);
int recv_packet(int s, gss_buffer_desc * out, 
			struct sockaddr_in * peer);
void log(int level, char * fmt, ...);
OM_uint32 get_seq(struct sockaddr_in * peer);
void free_packet(struct pbuff * buff);
struct pbuff * get_packet(struct sockaddr_in * addr, OM_uint32 seq, 
			OM_uint32 len, int * bs);

