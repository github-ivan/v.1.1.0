/* 
 * File:   learn_awl.h
 * Author: drordas
 *
 * Created on 19 de septiembre de 2011, 17:23
 */

#ifndef _LEARN_AXL_H_
#define	_LEARN_AXL_H_

#include "db_utils.h"

#define SPAM 1
#define HAM 0

#define default_axl_db "axl.db"
#define default_axl_dump_file "dump_axl.dat"

typedef struct axl_info axl_info;

int get_axl_data(DB *dbp,char *content, axl_info **axl_data     );

void add_axl_data(DB *dbp,char *content, short isspam);

short get_axl_ham(axl_info *axl_data);

short get_axl_spam(axl_info *axl_data);

void free_axl_data(axl_info *axl_data);

void load_axl_file(char *file_path, char *db_path);

void axl_print(char *db_path);

void axl_dump(char *db_path,char *file_path);

void axl_load(char *file_path, char *db_path);

#endif	/* LEARN_AWL_H */

