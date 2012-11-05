/* 
 * File:   sh_utils.h
 * Author: noemi
 *
 * Created on 23 de junio de 2011, 17:59
 */

#ifndef _SH_UTILS_H
#define	_SH_UTILS_H

struct spamhunting_db{
    DB *tokensdb;
    DB *pairsdb;
    DB *emaildb;
    DBC *cursor;
    DB_ENV *env;
};

typedef struct spamhunting_db spamhunting_db;

int scan_sh(char *mail, spamhunting_db *databases);

#endif	/* SH_UTILS_H */

