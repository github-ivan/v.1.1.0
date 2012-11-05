/* 
 * File:   db_utils.h
 * Author: drordas
 *
 * Created on 20 de septiembre de 2011, 14:15
 */

#ifndef _DB_UTILS_H_
#define	_DB_UTILS_H_

#include <db.h>

//DB HANDLER ERRORS
#define DB_OK 1
#define DB_FAIL 0
#define DB_CLOSED -1

//HASH ERRORS
#define HASH_FAIL -2

//DB SEARCH ERRORS
#define TOKEN_FOUND -1
#define TOKEN_MISSING -2

#define OPT_SPAM 0
#define OPT_HAM 1

#define MAGIC_TOKEN ""

char *loademail(char *path);
int create_env(DB_ENV **env, char *env_path);
int create_db_conexion(DB **dbp, DB_ENV *env, char *db_path, u_int32_t db_flags);
int create_db_dup_conexion(DB **dbp, DB_ENV *env, char *db_path, u_int32_t db_flags);
int close_db_conexion(DB **dbp, char *db_path);

char *get_hash(char *token);
char *get_full_hash(char *text);


#endif	/* DB_UTILS_H */

