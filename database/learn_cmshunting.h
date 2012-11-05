/***************************************************************************
*
*   File    : learn_cmshunting.c
*   Purpose : library for loading and storing email tokens in DBD
*
*
*   Original Author: Noemí Pérez Díaz
*
*   Date    : March  17, 2011
*
*****************************************************************************
*   LICENSING
*****************************************************************************
*
* WB4Spam: An ANSI C is an open source, highly extensible, high performance and
* multithread spam filtering platform. It takes concepts from SpamAssassin project
* improving distinct issues.
*
* Copyright (C) 2010, by Sing Research Group (http://sing.ei.uvigo.es)
*
* This file is part of WireBrush for Spam project.
*
* Wirebrush for Spam is free software; you can redistribute it and/or
* modify it under the terms of the GNU Lesser General Public License as
* published by the Free Software Foundation; either version 3 of the
* License, or (at your option) any later version.
*
* Wirebrush for Spam is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser
* General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
*
***********************************************************************/

#ifndef _LEARN_SPAMHUNTING_H__
#define	_LEARN_SPAMHUNTING_H__

/*---------------------------------------------------------------------------
                                                                       MACROS
 ---------------------------------------------------------------------------*/

//#define OPT_SPAM 1
//#define OPT_HAM 0

//#define MAGIC_TOKEN ""

#include <db.h>
#include "hashmap.h"
#include "db_utils.h"

//#define DB_OK 1
//#define DB_FAIL 0

//#define TOKEN_FOUND 0
//#define TOKEN_MISSING 1
//#define HASH_FAIL 2

/*---------------------------------------------------------------------------
   	       							     INCLUDES
 ---------------------------------------------------------------------------*/

#include <db.h>
#include "hashmap.h"
#include "linkedhashmap.h"
//#include "linked_list.h"

/*---------------------------------------------------------------------------
                                                                   DATA TYPES
 ---------------------------------------------------------------------------*/
/* A container for spamhunting databases and cursors*/
struct databases {
    /* Pointer to tokens database*/
    DB *tokens;
    /* Pointer to email database*/
    DB *email;
    /* Pointer to pairs database*/
    DB *pairs;
    /* Cursor for pairs database*/
    DBC *cursor;
};

/* A short hand typedef for databases structure */
typedef struct databases databases;

/* A container for tokenize information.*/
struct keys {
    /* Hashmap that contains the tokens of an e-mail.*/
    map_t tokens;
    /* The message id of an e-mail.*/
    char *message_id;
};

/* A short hand typedef for keys structure */
typedef struct keys keys;


/* A container for token information.*/
struct tokensdata {
    /* Number of spam messages that contains the token.*/
    int spam_count;
    /* Number of ham messages that contains the token.*/
    int ham_count;
};

struct messageoccur{
    char *message_id;
    int occurrences;
};

typedef struct messageoccur messageoccur;

/* A short hand typed
 * ef for tokensdata structure */
typedef struct tokensdata tokensdata;

/*---------------------------------------------------------------------------
                                                                    FUNCTIONS
 ---------------------------------------------------------------------------*/

/* Assigns the path for dump spamhunting databases.*/
void set_dump_path_sh(char *out_path);

/* Assigns the path for load spamhunting databases.*/
void set_load_path_sh(char *load_path);

/* Assigns the path for tokens database.*/
//void set_tokens_database_path(char *tokenspath);

/* Assigns the path for email database.*/
//void set_email__database_path(char *emailpath);

/* Assigns the path for pairs database.*/
//void set_pairs_database_path(char *pairspath);

/* Returns the tokens database path.*/
//char *get_tokens_database_path();

/* Returns the email database path.*/
//char *get_email_database_path();

/* Returns the pairs database path.*/
//char *get_pairs_database_path();

/* Creates and opens a database conexion.*/
//int create_db_conexion_sh(DB **dbp, DB_ENV *env, char *db_path, u_int32_t db_flags);//DB_ENV *env, char *db_path, u_int32_t db_flags);

/* Creates and opens a database conexion (database with duplicates).*/
//int create_db_dup_conexion_sh(DB **dbp, DB_ENV *env, char *db_path, u_int32_t db_flags);//DB_ENV *env, char *db_path, u_int32_t db_flags);


/*--------------------FUNCTIONS FOR TOKEN DATABASE-----------------------------*/

/**
 * Establishes the number of spam and ham messages that contains a token
 * This information is recorded in a struct.
 */
//void set_data_token_sh(tokensdata **tok,const int ham, const int spam);

int store_spam_sh(void *dbs, void *message_id, void *token);
int store_ham_sh(void *dbs, void *message_id, void *token);
/**
 * Returns a struct with the number of spam and ham messages of a token
 * stored in tokens database.
 */
int get_data_token_sh(DB *dbp,char *token, tokensdata *dat);

/* Stores a struct with the number of spam and ham messages in tokens database.*/
//void store_magic_token_sh(DB * dbp, int type);

/*--------------------FUNCTIONS FOR PAIRS DATABASE-----------------------------*/

/* Returns a linkedhashmap with the message id of a token.*/
int get_data_pairs_sh(DB *dbp,char *token, linkedhashmap **pairslist);

/*--------------------FUNCTIONS FOR EMAIL DATABASE-----------------------------*/

/* Returns the class of a message_id. */
int get_data_email_sh(DB *dbp,char *email, int *class);

/*--------------------------MAIN FUNCTIONS------------------------------------*/

/* Loads the emails contained in a path and stores its information in three databases.*/
void load_directory_mail_sh(char *directory, int type);

/* Exports tokens database to a file.*/
void db_dump_tokens(char *db_path);

/* Exports email database to a file.*/
void db_dump_email(char *db_path);

/* Exports pairs database to a file.*/
void db_dump_pairs(char *db_path);

/* Imports tokens database from a file.*/
void db_load_tokens();

/* Imports email database from a file.*/
void db_load_email();

/* Imports pairs database from a file.*/
void db_load_pairs();

void free_tokenize_sh(keys *_key);

#endif

