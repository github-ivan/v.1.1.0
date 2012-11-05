/***************************************************************************
*
*   File    : test.c
*   Purpose : Test pcre_regular_expressions
*
*   Author: David Ruano
*
*
*   Date    : December 9, 2010
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

#include <stdio.h>
#include <stdlib.h>
#include "pcre_regex_util.h"

/*
 * 
 */
int main(int argc, char** argv) {

    char *text="alsjaslkdjsaldjslakdjasldjasldjsakjdaj nns dkjsd asñlkdjasdkljs ñlkasjd s asdasd";

    pcre *ret = pcregex_compile("(?i:asd)");
    if(pcregex_match(ret,text)==1){
        printf("HAY\n");
    }
    else
        printf("No hay\n");

    pcre_free(ret);
    return (EXIT_SUCCESS);
}

