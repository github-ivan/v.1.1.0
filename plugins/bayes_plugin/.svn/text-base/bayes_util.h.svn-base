/* 
 * File:   bayes_util.h
 * Author: drordas
 *
 * Created on 29 de febrero de 2012, 10:37
 */

#ifndef BAYES_UTIL_H
#define	BAYES_UTIL_H

#include <db.h>
#include <cpluff.h>
#include "cache.h"
#include "eml_parser.h"
#include "tokenize.h"
#include "probabilities.h"
//#include "learn_bayes_utils.h"
#include "core.h"
#include "iniparser.h"


//DEFAULT DEFINITION VALUES ->IF NOT INCLUDED IN CONFIG FILE.
#define DEFAULT_BAYES_DATABASE_PATH "wb4spam_bayes.db"
#define DEFAULT_CMS_BAYES_DATABASE_PATH "wb4cms_bayes.db"
#define BAYES_ENV_PATH "database/"
#define NONE 0
#define DEFAULT_MIN_NSPAM 0
#define DEFAULT_MIN_NHAM 0
#define DEFAULT_REQUIRE_SIGNIFFICANT_TOKENS_TO_SCORE 1
#define DEFAULT_CACHE_SIZE 5

struct bayes_config{
  int min_nspam;
  int min_nham;
  int require_significant_tokens;
  int cache_size;
  char *database_path;  
  int is_config_passed;
};
typedef struct bayes_config bayes_config;

struct bayes_data{
  DB *dbp;
  DB_ENV *env;
  cache_data *cache;
  function_t *funcs;
  eventhandler_t *events;
  cp_context_t *ctx;
  bayes_config *config;
};
typedef struct bayes_data bayes_data;

long double scan_mail(char *mail, DB *dbp, bayes_config *config);
int free_node(element p);
int setlistprob(any_t list_prob, any_t info, any_t token);
int compare (element a, element b);
void free_cache_data(element item);
int free_bayes_cache(element elem);

#endif	/* BAYES_UTIL_H */

