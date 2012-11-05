/***************************************************************************
*
*   File    : learn_bayes.h
*   Purpose : library for loading and storing email tokens in DBD
*
*
*   Original Author: David Ruano Ordás
*
*   Date    : January  4, 2011
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

#ifndef _LEARN_BAYES_UTILS_H_
#define	_LEARN_BAYES_UTILS_H_

#define BAYES_LEARN_ENV_PATH "."

/*---------------------------------------------------------------------------
   	       							     INCLUDES
 ---------------------------------------------------------------------------*/

#include <db.h>
#include "hashmap.h"
#include "db_utils.h"

/*---------------------------------------------------------------------------
                                                                       MACROS
 ---------------------------------------------------------------------------*/

//#define OPT_SPAM 0
//#define OPT_HAM 1

//#define MAGIC_TOKEN ""

//#define DB_OK 1
//#define DB_FAIL 0
//#define DB_CLOSED -1
//#define HASH_FAIL 2;

/*---------------------------------------------------------------------------
                                                                   DATA TYPES
 ---------------------------------------------------------------------------*/

/* A container for token information.*/
struct tokendata {
    /* Spam probability of the token.*/
    float probability;
    /* Number of spam messages that contains the token.*/
    long int spam_count;
    /* Number of ham messages that contains the token.*/
    long int ham_count;
};

/* A short hand typedef for tokendata structure */
typedef struct tokendata tokendata;

/*---------------------------------------------------------------------------
                                                                    FUNCTIONS
 ---------------------------------------------------------------------------*/

void db_print(char *db_path);

/* Loads an email from a path.*/
//char *loademail(char * path);

/*
 * Establishes the number of spam and ham messages that contains a token
 * and initializes its probability.
 * This information is recorded in a struct.
 */
void set_data_token(tokendata **tok,int ham,int spam);

/* Sets the probability of a token.*/
void set_prob_token(tokendata **tok,const float prob);

/* Assigns the path for storing bayes database.*/
//void set_database_path(char *dbpath);

/* Assigns the path for dump bayes database.*/
//void set_dump_path(char *db_dump_path);

/* Creates and opens a database conexion.*/
//int create_db_conexion(DB **dbp, char *db_path, u_int32_t db_flags);

/*
 * Flushes any cached database information to disk, closes any open cursors,
 * frees any allocated resources, and closes any underlying files.
 */
//void close_db_conexion(DB **dbp, char *db_path);

int store_spam(void *dbp, void *token);
int store_ham(void *dbp, void *token);
/*
 * Returns a struct with the probability and the number of spam and ham messages of a token
 * stored in a database.
 */
int get_data_token(DB *dbp, char *token, tokendata *dat);

/* Exports a berkeley database to a file.*/
void db_dump(char *db_path,char *file_path);

/* Imports a berkeley database from a file.*/
void db_load(char *file_path, char *db_path);

/* Returns the path of bayes database.*/
char *get_database_path();

void db_print(char *db_path);

/* Stores the tokens of an e-mail in a berkeley database.*/
void store_mail(DB *dbp,map_t tokens,short type);

#endif

