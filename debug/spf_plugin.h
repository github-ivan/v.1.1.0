/* 
 * File:   spf_plugin.h
 * Author: drordas
 *
 * Created on 18 de julio de 2012, 13:40
 */

#ifndef SPF_PLUGIN_H
#define	SPF_PLUGIN_H

#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <spf2/spf.h>
#include "cache.h"

struct check_spf_data{
  SPF_server_t    *spf_server;
  cache_data *cache;
};

typedef struct check_spf_data spf_data;

spf_data *create_spf();
void destroy_spf(spf_data *data);

int spf_softfail(void *_data, void *content, char *params);
int spf_fail(void *_data, void *content, char *params);
int spf_neutral(void *_data, void *content, char *params);
int spf_none(void *_data, void *content, char *params);
int spf_pass(void *_data, void *content, char *params);

#endif	/* SPF_PLUGIN_H */

