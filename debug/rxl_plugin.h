/* 
 * File:   rxl_plugin.h
 * Author: drordas
 *
 * Created on 18 de julio de 2012, 13:32
 */

#ifndef RXL_PLUGIN_H
#define	RXL_PLUGIN_H

#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <spf2/spf.h>
#include <arpa/inet.h>
#include "cache.h"

struct rxl_data {
    cache_data *cache;
    SPF_server_t *spf_server;
};
typedef struct rxl_data rxl_data;

rxl_data *create_rxl();
void destroy_rxl(rxl_data *data);
int rxl_check(rxl_data *data,void *content, char *params);

#endif	/* RXL_PLUGIN_H */

