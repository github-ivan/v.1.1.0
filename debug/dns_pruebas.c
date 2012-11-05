/* 
 * File:   dns_pruebas.c
 * Author: drordas
 *
 * Created on 27 de junio de 2012, 13:16
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <spf2/spf.h>
#include <spf2/spf_dns.h>
#include <spf2/spf_dns_test.h>
#include <spf2/spf_dns_resolv.h>


#include <arpa/inet.h>
/*
 * 
 */
int main(int argc, char** argv) {

    //SPF_dns_server_t *dns_server;
    SPF_server_t *spf_server = NULL;
    SPF_dns_rr_t *spf_dns_rr=NULL;
    
    spf_server = SPF_server_new(SPF_DNS_CACHE, 1);
    
    //struct in_addr addr;
    
    //if(!inet_pton(AF_INET,"193.146.32.86",&addr)){
    //    printf("Error converting IP");
    //}
    char str[INET_ADDRSTRLEN];
    
    //spf_dns_rr=SPF_dns_lookup(spf_server->resolver,"2.87.19.172.zen.spamhaus.org",ns_t_a,0);
    spf_dns_rr=SPF_dns_lookup(spf_server->resolver,"1.72.122.72.zen.spamhaus.org",ns_t_a,0);
    //spf_dns_rr=SPF_dns_lookup(spf_server->resolver,"www.spamhaus.org",ns_t_a,1); 
    

    if ( spf_dns_rr->herrno == NETDB_SUCCESS || spf_dns_rr->herrno == NO_DATA){        
        printf("DNS lookup correct\n");
        printf("\t\t---> %s\n",inet_ntop(AF_INET,&(spf_dns_rr->rr[0]->a),str,INET_ADDRSTRLEN));
    }else{ 
        printf( "DNS lookup failed\n");
    }
    
    //if (spf_dns_rr) SPF_dns_rr_free(spf_dns_rr);
    if (spf_dns_rr) SPF_dns_rr_free(spf_dns_rr);        
    if (spf_server) SPF_server_free(spf_server);
    
    
    spf_dns_rr=NULL;
    spf_server=NULL;
    //SPF_dns_free(spf_server->resolver);
    
    //SPF_server_free(spf_server);
    
    return (EXIT_SUCCESS);
}

