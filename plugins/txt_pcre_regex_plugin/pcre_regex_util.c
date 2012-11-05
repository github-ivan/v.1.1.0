/***************************************************************************
*
*   File    : pcre_regex_util.c
*   Purpose : Simplify the usage of pcre_regex functionality
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
#include <string.h>
#include "pcre_regex_util.h"

#define OVECCOUNT 3

pcre *pcregex_compile(const char *pattern){
    const char *error;
    int erroffset;
    pcre *reg=NULL;
    
    if((reg=pcre_compile(pattern,0,&error,&erroffset,NULL))==NULL){
        printf("PCRE compilation failed at offset %d: %s\n", erroffset, error);
        return NULL;
    }
    else{
        return reg;
    }
}

int pcregex_match(const pcre *reg, const char *string){
    int ovector[OVECCOUNT];
    if((pcre_exec(reg,NULL,string,strlen(string),0,0,ovector,OVECCOUNT))<0){
        return 0;
    }
    else{
        return 1;
    }
}

void pcregex_free(pcre *reg){    
    pcre_free(reg);
}

