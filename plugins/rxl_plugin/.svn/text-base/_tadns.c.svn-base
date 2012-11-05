/*
 * Copyright (c) 2004-2005 Sergey Lyubka <valenok@gmail.com>
 *
 * "THE BEER-WARE LICENSE" (Revision 42):
 * Sergey Lyubka wrote this file.  As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return.
 */

#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>
#include "logger.h"

#ifdef _WIN32
#pragma comment(lib,"ws2_32")
#pragma comment(lib,"advapi32")
#include <winsock.h>
typedef	int		socklen_t;
typedef	unsigned char	uint8_t;
typedef	unsigned short	uint16_t;
typedef	unsigned int	uint32_t;
#else
#define	closesocket(x)	close(x)
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <unistd.h>
#endif /* _WIN32 */

#include "_tadns.h"
#include "llist.h"

#define	DNS_MAX			1025	/* Maximum host name		*/
#define	DNS_PACKET_LEN		2048	/* Buffer size for DNS packet	*/
#define	MAX_CACHE_ENTRIES	10000	/* Dont cache more than that	*/

/*
 * User query. Holds mapping from application-level ID to DNS transaction id,
 * and user defined callback function.
 */
struct query {
    struct llhead   link;		/* Link				*/
    time_t          expire;		/* Time when this query expire	*/
    uint16_t        tid;		/* UDP DNS transaction ID	*/
    uint16_t        qtype;		/* Query type			*/
    char            name[DNS_MAX];	/* Host name			*/
    void            *ctx;		/* Application context		*/
    dns_callback_t  callback;           /* User callback routine	*/
    unsigned char   addr[DNS_MAX];	/* Host address			*/
    size_t          addrlen;            /* Address length		*/
};

//query_result result;
/*
 * Resolver descriptor.
 */
struct dns {
    int	sock;		/* UDP socket used for queries	*/
    struct sockaddr_in sa;		/* DNS server socket address	*/
    uint16_t	tid;		/* Latest tid used		*/

    struct llhead	active;		/* Active queries, MRU order	*/
    struct llhead	cached;		/* Cached queries		*/
    int	num_cached;	/* Number of cached queries	*/
};

/*
 * DNS network packet
 */
struct header {
    uint16_t	tid;		/* Transaction ID		*/
    uint16_t	flags;		/* Flags			*/
    uint16_t	nqueries;	/* Questions			*/
    uint16_t	nanswers;	/* Answers			*/
    uint16_t	nauth;		/* Authority PRs		*/
    uint16_t	nother;		/* Other PRs			*/
    unsigned char	data[1];	/* Data, variable length	*/
};

void get_response(struct dns *_dns, struct header *_header, const unsigned char *_p, struct query *_q,
                  int len, const unsigned char *_e, query_result **q_result);

/*
 * Return UDP socket used by a resolver
 */
int dns_get_fd(struct dns *dns)
{
	return (dns->sock);
}

/*
 * Fetch name from DNS packet
 */
static void fetch(const uint8_t *pkt, const uint8_t *s, int pktsiz, char *dst, int dstlen)
{
	const uint8_t	*e = pkt + pktsiz;
	int		j, i = 0, n = 0;


	while (*s != 0 && s < e) {
		if (n > 0)
			dst[i++] = '.';

		if (i >= dstlen)
			break;

		if ((n = *s++) == 0xc0) {
			s = pkt + *s;	/* New offset */
			n = 0;
		} else {
			for (j = 0; j < n && i < dstlen; j++)
				dst[i++] = *s++;
		}
	}

	dst[i] = '\0';
}

/*
 * Case-insensitive string comparison, a-la strcmp()
 */
static int casecmp(register const char *s1, register const char *s2)
{
	for (; *s1 != '\0' && *s2 != '\0'; s1++, s2++)
		if (tolower(*s1) != tolower(*s2))
			break;

	return (*s1 - *s2);
}

/*
 * Put given file descriptor in non-blocking mode. return 0 if success, or -1
 */
static int nonblock(int fd)
{
#ifdef	_WIN32
	unsigned long	on = 1;
	return (ioctlsocket(fd, FIONBIO, &on));
#else
	int	flags;

	flags = fcntl(fd, F_GETFL, 0);

	return (fcntl(fd, F_SETFL, flags | O_NONBLOCK));
#endif /* _WIN32 */
}

/*
 * Find what DNS server to use. Return 0 if OK, -1 if error
 */
static int getdnsip(struct dns *dns)
{
	int	ret = 0;

#ifdef _WIN32
	int	i;
	LONG	err;
	HKEY	hKey, hSub;
	char	subkey[512], dhcpns[512], ns[512], value[128], *key =
	"SYSTEM\\ControlSet001\\Services\\Tcpip\\Parameters\\Interfaces";

	if ((err = RegOpenKey(HKEY_LOCAL_MACHINE,
	    key, &hKey)) != ERROR_SUCCESS) {
		fprintf(stderr, "cannot open reg key %s: %d\n", key, err);
		ret--;
	} else {
		for (ret--, i = 0; RegEnumKey(hKey, i, subkey,
		    sizeof(subkey)) == ERROR_SUCCESS; i++) {
			DWORD type, len = sizeof(value);
			if (RegOpenKey(hKey, subkey, &hSub) == ERROR_SUCCESS &&
			    (RegQueryValueEx(hSub, "NameServer", 0,
			    &type, value, &len) == ERROR_SUCCESS ||
			    RegQueryValueEx(hSub, "DhcpNameServer", 0,
			    &type, value, &len) == ERROR_SUCCESS)) {
				dns->sa.sin_addr.s_addr = inet_addr(value);
				ret++;
				RegCloseKey(hSub);
				break;
			}
		}
		RegCloseKey(hKey);
	}
#else
	FILE	*fp;
	char	line[512];
	int	a, b, c, d;

	if ((fp = fopen("/etc/resolv.conf", "r")) == NULL) {
		ret--;
	} else {
		/* Try to figure out what DNS server to use */
		for (ret--; fgets(line, sizeof(line), fp) != NULL; ) {
			if (sscanf(line, "nameserver %d.%d.%d.%d",
			   &a, &b, &c, &d) == 4) {
				dns->sa.sin_addr.s_addr =
				    htonl(a << 24 | b << 16 | c << 8 | d);
				ret++;
				break;
			}
		}
		(void) fclose(fp);
	}
#endif /* _WIN32 */

	return (ret);
}

struct dns *dns_init(void)
{
	struct dns	*dns;
	int		rcvbufsiz = 128 * 1024;

#ifdef _WIN32
	{ WSADATA data; WSAStartup(MAKEWORD(2,2), &data); }
#endif /* _WIN32 */

	/* FIXME resource leak here */
	if ((dns = (struct dns *) calloc(1, sizeof(*dns))) == NULL)
		return (NULL);
	else if ((dns->sock = socket(PF_INET, SOCK_DGRAM, 17)) == -1)
		return (NULL);
	else if (nonblock(dns->sock) != 0)
		return (NULL);
	else if (getdnsip(dns) != 0)
		return (NULL);

	dns->sa.sin_family	= AF_INET;
	dns->sa.sin_port	= htons(53);

	/* Increase socket's receive buffer */
	(void) setsockopt(dns->sock, SOL_SOCKET, SO_RCVBUF,
	    (char *) &rcvbufsiz, sizeof(rcvbufsiz));

	LL_INIT(&dns->active);
	LL_INIT(&dns->cached);

	return (dns);
}

static void destroy_query(struct query *query)
{
	LL_DEL(&query->link);
	free(query);
}

/*
 * Find host in host cache. Add it if not found.
 */
static struct query *find_cached_query(struct dns *dns, enum dns_query_type qtype, const char *name)
{
	struct llhead	*lp, *tmp;
	struct query	*query;

	LL_FOREACH_SAFE(&dns->cached, lp, tmp) {
		query = LL_ENTRY(lp, struct query, link);

		if (query->qtype == qtype && casecmp(name, query->name) == 0) {
			/* Keep sorted by LRU: move to the head */
			LL_DEL(&query->link);
			LL_ADD(&dns->cached, &query->link);
			return (query);
		}
	}

	return (NULL);
}

static struct query *find_active_query(struct dns *dns, uint16_t tid)
{
	struct llhead	*lp;
	struct query	*query;

	LL_FOREACH(&dns->active, lp) {
		query = LL_ENTRY(lp, struct query, link);
		if (tid == query->tid)
			return (query);
	}

	return (NULL);
}

/*
 * User wants to cancel query
 */
void dns_cancel(struct dns *dns, const void *context)
{
	struct llhead	*lp, *tmp;
	struct query	*query;

	LL_FOREACH_SAFE(&dns->active, lp, tmp) {
		query = LL_ENTRY(lp, struct query, link);

		if (query->ctx == context) {
			destroy_query(query);
			break;
		}
	}
}

static void call_user(struct dns *dns, struct query *query, 
                      enum dns_error error, query_result **q_result)
{
	struct dns_cb_data	cbd;

	cbd.context	= query->ctx;
	cbd.query_type	= (enum dns_query_type) query->qtype;
	cbd.error	= error;
	cbd.name	= query->name;
	cbd.addr	= query->addr;
	cbd.addr_len	= query->addrlen;

	query->callback(&cbd,q_result);

	/* Move query to cache */
	LL_DEL(&query->link);
	LL_ADD(&dns->cached, &query->link);
	dns->num_cached++;
	if (dns->num_cached >= MAX_CACHE_ENTRIES) {
		query = LL_ENTRY(dns->cached.prev, struct query, link);
		destroy_query(query);
		dns->num_cached--;
	}
}

static void parse_udp(struct dns *dns, const unsigned char *pkt, int len,
                      query_result **q_result)
{
	struct header		*header;
	const unsigned char	*p, *e;//, *s;
	struct query		*q;
	uint16_t		type;
	int			stop, dlen, nlen;

	/* We sent 1 query. We want to see more that 1 answer. */
	header = (struct header *) pkt;
	if (ntohs(header->nqueries) != 1)
		return;

	/* Return if we did not send that query */
	if ((q = find_active_query(dns, header->tid)) == NULL)
		return;

	/* Received 0 answers */
	if (header->nanswers == 0) {
		q->addrlen = 0;
		call_user(dns, q, DNS_DOES_NOT_EXIST,q_result);
		return;
	}
	/* Skip host name */
	for (e = pkt + len, nlen = 0, p = &header->data[0];
	    p < e && *p != '\0'; p++)
		nlen++;

#define	NTOHS(p)	(((p)[0] << 8) | (p)[1])

	/* We sent query class 1, query type 1 */
	if (&p[5] > e || NTOHS(p + 1) != q->qtype)
		return;

	/* Go to the first answer section */
	p += 5;

	/* Loop through the answers, we want A type answer */
	for (stop = 0; !stop && &p[12] < e; ) {

		/* Skip possible name in CNAME answer */
		if (*p != 0xc0) {
			while (*p && &p[12] < e)
				p++;
			p--;
		}

		type = htons(((uint16_t *)p)[1]);

		if (type == 5) {
			/* CNAME answer. shift to the next section */
			dlen = htons(((uint16_t *) p)[5]);
			p += 12 + dlen;
		} else if (type == q->qtype) {
			//found = stop = 1;
                        get_response(dns,header, p, q,len,e,q_result);
                        dlen = htons(((uint16_t *) p)[5]);
			p += 12 + dlen;
		} else {
			stop = 1;
		}
	}
}

void get_response(struct dns *_dns, struct header *_header, const unsigned char *_p, struct query *_q,
                  int len, const unsigned char *_e, query_result **q_result)
{
    uint32_t	ttl;
    char	name[1025];

    int dlen;
    dlen = htons(((uint16_t *) _p)[5]);
    _p += 12;

    if (_p + dlen <= _e) {
        //Add to the cache
        (void) memcpy(&ttl, _p - 6, sizeof(ttl));
        _q->expire = time(NULL) + (time_t) ntohl(ttl);

        //Call user
        if (_q->qtype == DNS_MX_RECORD) {
            fetch((uint8_t *) _header, _p + 2,
                  len, name, sizeof(name) - 1);
            _p = (const unsigned char *) name;
            dlen = strlen(name);
//            printf("NAME: %s\n",name);
        }
        _q->addrlen = dlen;
        if (_q->addrlen > sizeof(_q->addr))
            _q->addrlen = sizeof(_q->addr);
        (void) memcpy(_q->addr, _p, _q->addrlen);
                      call_user(_dns, _q, DNS_OK,q_result);
    }
}

int dns_poll(struct dns *dns, query_result **q_result)
{
	struct llhead		*lp, *tmp;
	struct query		*query;
	struct sockaddr_in	sa;
	socklen_t		len = sizeof(sa);
	int			n, num_packets = 0;
	unsigned char		pkt[DNS_PACKET_LEN];
	time_t			now;

	now = time(NULL);

	/* Check our socket for new stuff */
	while ((n = recvfrom(dns->sock, pkt, sizeof(pkt), 0,
	    (struct sockaddr *) &sa, &len)) > 0 &&
	    n > (int) sizeof(struct header)) {
		parse_udp(dns, pkt, n,q_result);
		num_packets++;
	}

	/* Cleanup expired active queries */
	LL_FOREACH_SAFE(&dns->active, lp, tmp) {
		query = LL_ENTRY(lp, struct query, link);

		if (query->expire < now) {
			query->addrlen = 0;
			call_user(dns, query, DNS_TIMEOUT,q_result);
			destroy_query(query);
		}
	}

	/* Cleanup cached queries */
	LL_FOREACH_SAFE(&dns->cached, lp, tmp) {
		query = LL_ENTRY(lp, struct query, link);
		if (query->expire < now) {
			destroy_query(query);
			dns->num_cached--;
		}
	}

	return (num_packets);
}

/*
 * Cleanup
 */
void dns_fini(struct dns *dns)
{
	struct llhead	*lp, *tmp;
	struct query	*query;

	if (dns->sock != -1)
		(void) closesocket(dns->sock);

	LL_FOREACH_SAFE(&dns->active, lp, tmp) {
		query = LL_ENTRY(lp, struct query, link);
		destroy_query(query);
	}

	LL_FOREACH_SAFE(&dns->cached, lp, tmp) {
		query = LL_ENTRY(lp, struct query, link);
		destroy_query(query);
		dns->num_cached--;
	}

	free(dns);
}

/*
 * Queue the resolution
 */
void dns_queue(struct dns *dns, void *ctx, const char *name,
		enum dns_query_type qtype, dns_callback_t callback, query_result **q_result)
{
	struct query	*query;
	struct header	*header;
	int		i, n, name_len;
	char		pkt[DNS_PACKET_LEN], *p;
	const char 	*s;
	time_t		now = time(NULL);
	struct dns_cb_data cbd;


	/* XXX Search the cache first */
	if ((query = find_cached_query(dns, qtype, name)) != NULL) {
		query->ctx = ctx;
		call_user(dns, query, DNS_OK, q_result);
		if (query->expire < now) {
			destroy_query(query);
			dns->num_cached--;
		}
		return;
	}

	/* Allocate new query */
	if ((query = (struct query *) calloc(1, sizeof(*query))) == NULL) {
		(void) memset(&cbd, 0, sizeof(cbd));
		cbd.error = DNS_ERROR;
		callback(&cbd,q_result);
		return;
	}

	/* Init query structure */
	query->ctx	= ctx;
	query->qtype	= (uint16_t) qtype;
	query->tid	= ++dns->tid;
	query->callback	= callback;
	query->expire	= now + DNS_QUERY_TIMEOUT;
	for (p = query->name; *name &&
	    p < query->name + sizeof(query->name) - 1; name++, p++)
		*p = tolower(*name);
	*p = '\0';
	name = query->name;

	/* Prepare DNS packet header */
	header		= (struct header *) pkt;
	header->tid	= query->tid;
	header->flags	= htons(0x100);		/* Haha. guess what it is */
	header->nqueries= htons(1);		/* Just one query */
	header->nanswers= 0;
	header->nauth	= 0;
	header->nother	= 0;

	/* Encode DNS name */

	name_len = strlen(name);
	p = (char *) &header->data;	/* For encoding host name into packet */

	do {
		if ((s = strchr(name, '.')) == NULL)
			s = name + name_len;

		n = s - name;			/* Chunk length */
		*p++ = n;			/* Copy length */
		for (i = 0; i < n; i++)		/* Copy chunk */
			*p++ = name[i];

		if (*s == '.')
			n++;

		name += n;
		name_len -= n;

	} while (*s != '\0');

	*p++ = 0;			/* Mark end of host name */
	*p++ = 0;			/* Well, lets put this byte as well */
	*p++ = (unsigned char) qtype;	/* Query Type */

	*p++ = 0;
	*p++ = 1;			/* Class: inet, 0x0001 */

	assert(p < pkt + sizeof(pkt));
	n = p - pkt;			/* Total packet length */

	if (sendto(dns->sock, pkt, n, 0,
	    (struct sockaddr *) &dns->sa, sizeof(dns->sa)) != n) {
		(void) memset(&cbd, 0, sizeof(cbd));
		cbd.error = DNS_ERROR;
		callback(&cbd, q_result);
		destroy_query(query);
	}

	LL_TAIL(&dns->active, &query->link);
}
/*
void free_global_result(){
    if(result.value!=NULL)
       free(result.value);
    result.addlen=0;
    result.error=DNS_ERROR;
    result.value=NULL;
}
*/
void free_query_result(query_result *q_res){
    if(q_res!=NULL){
        if(q_res->value!=NULL)
            free(q_res->value);
        free(q_res);
    }
}

//query_result *get_result_struct(){
//    return result;
//}

//unsigned char *get_result_value(){
//    return result->value;
//}

//enum dns_query_type get_result_query_type(){
//    return result->query_type;
//}

//enum dns_error get_result_error(){
//    return result->error;
//}

static void callback(struct dns_cb_data *cbd, struct query_result **q_result)
{       
    if(cbd->error==DNS_OK){
        *q_result=(query_result *)malloc(sizeof(query_result));
        (*q_result)->value=malloc(sizeof(unsigned char)*cbd->addr_len+1);
        (*q_result)->error=cbd->error;
        memcpy((*q_result)->value,cbd->addr,sizeof(unsigned char)*cbd->addr_len);
        (*q_result)->value[cbd->addr_len]='\0';
        (*q_result)->addlen=cbd->addr_len;
        (*q_result)->query_type=cbd->query_type;
    }else *q_result=NULL;
}

int create_dns_query(char *domain,enum dns_query_type qtype,struct timeval tv,
                     query_result **q_result){

    struct dns	*dns;
    fd_set set;
    
    if ((dns = dns_init()) == NULL) {
        wblprintf(LOG_CRITICAL,"TADNS","Could not init dns resolver\n");
        *q_result=NULL;
        return DNS_ERROR; 
    }

    dns_queue(dns, &domain, domain, qtype, callback, q_result);

    FD_ZERO(&set);
    FD_SET(dns_get_fd(dns), &set);

    if (select(dns_get_fd(dns) + 1, &set, NULL, NULL, &tv) == 1)
            dns_poll(dns,q_result);

    dns_fini(dns);

    if(*q_result==NULL) return DNS_ERROR;
    else return (*q_result)->error;
}

/*
int main(int argc,char *argv[]){
    char *domain=argv[1];
    struct timeval tv= {1,0};
    query_result *resultado;
    if(create_dns_query(domain,DNS_A_RECORD,tv,&resultado)==DNS_OK){
        printf("HAY RESULTADO\n");
        printf("%u.%u.%u.%u\n",resultado->value[0],
                               resultado->value[1],resultado->value[2],
                               resultado->value[3]);
    }
    else
        printf("NO HAY RESULTADO\n");
    
    free_query_result(resultado);
    
}
*/
