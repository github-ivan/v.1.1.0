/***************************************************************************
*
*   File    : cache.h
*   Purpose : Implements a dinamic cache using hashmap and linkedlist.
*
*
*   Author: David Ruano Ordás
*
*
*   Date    : March  14, 2010
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

#ifndef _CACHE_H_
#define	_CACHE_H_

/*---------------------------------------------------------------------------
   								Includes
 ---------------------------------------------------------------------------*/

#include "common_dinamic_structures.h"

/*---------------------------------------------------------------------------
                                                                Macros
 ---------------------------------------------------------------------------*/

#define CACHE_FAIL -2
#define CACHE_UNDEF -3
#define CACHE_ELEM_EXIST -1
#define CACHE_ELEM_MISSING 0
#define CACHE_ELEM_FOUND 1
#define CACHE_OK 2

/*---------------------------------------------------------------------------
                                                                Data Types
 ---------------------------------------------------------------------------*/

struct cache_element{
    char *key;
    element data;
};

struct cache_data;

typedef struct cache_element cache_element;
typedef struct cache_data cache_data;
typedef cache_element *c_element;

typedef void (*PFKey)(element);
typedef void (*PFdata)(c_element);

cache_data *newcache(int max_size);

/*---------------------------------------------------------------------------
                                                         Function definition
 ---------------------------------------------------------------------------*/
int push_cache(cache_data *_cache, char *key,PFKey f, element elem);
int peek_cache(cache_data *_cache, char *key, element *elem);
int get_cache_size(cache_data *_cache);
void set_cache_size(cache_data *_cache,int size);
void free_cache(cache_data *cache,PFree f);

#endif	/* CACHE_H */

