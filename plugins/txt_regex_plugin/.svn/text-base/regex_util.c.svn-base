/***************************************************************************
*
*   File    : regex_util.h
*   Purpose : Simplify the usage of GNU regex library
*
*   Author: David Ruano, José Ramón Méndez
*
*
*   Date    : October  25, 2010
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

#include "regex_util.h"
#include <stdlib.h>

regex_t *rgx_compile(const char *pattern){
    regex_t *re=malloc(sizeof(regex_t));
	
    if (regcomp(re, pattern, REG_EXTENDED|REG_NOSUB) != 0){
	free(re);
        return NULL;
    }
	    
    else return re;
}

int rgx_match(const regex_t *re, const char *string){
    if (regexec(re, string, (size_t) 0, NULL, 0))
        return 0;
    else
        return 1;
}

void rgx_free(regex_t *re){
    regfree(re);
    free(re);
}
