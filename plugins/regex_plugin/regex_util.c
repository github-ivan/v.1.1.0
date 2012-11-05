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
#include "logger.h"
#include <stdlib.h>


regex_t *rgx_compile(const char *pattern){
    regex_t *re=malloc(sizeof(regex_t));
    int value=0;
    if ( (value = regcomp(re, pattern, REG_EXTENDED|REG_NOSUB) != REG_NOERROR) ){
        switch(value){
            case REG_BADPAT: 
                wblprintf(LOG_WARNING,"REGEX_UTIL","Invalid regular expresion: %s\n",pattern);
                break;
            case REG_EESCAPE: 
                wblprintf(LOG_WARNING,"REGEX_UTIL","Incorrect regular expresion. %s\n\t\t\t\t\t Invalid \\ \n",pattern);
                break;
            case REG_ESUBREG: 
                wblprintf(LOG_WARNING,"REGEX_UTIL","Incorrect regular expresion. %s.\n\t\t\t\t\t Invalid number in \\digit\n",pattern);
                break;
            case REG_EBRACK: 
                wblprintf(LOG_WARNING,"REGEX_UTIL","Incorrect regular expresion. %s.\n\t\t\t\t\t Imbalanced [ ]\n",pattern);
                break;
            case REG_EPAREN: 
                wblprintf(LOG_WARNING,"REGEX_UTIL","Incorrect regular expresion. %s.\n\t\t\t\t\t Imbalanced ( )\n",pattern);                
                break;
            case REG_EBRACE: 
                wblprintf(LOG_WARNING,"REGEX_UTIL","Incorrect regular expresion. %s.\n\t\t\t\t\tImbalanced { }\n",pattern);                
                break;
            case REG_BADBR: 
                wblprintf(LOG_WARNING,"REGEX_UTIL","Incorrect regular expresion. %s.\n\t\t\t\t\tInvalid content inside { }\n",pattern);                
                break;
            case REG_ERANGE: 
                wblprintf(LOG_WARNING,"REGEX_UTIL","Incorrect regular expresion. %s.\n\t\t\t\t\tInvalid endpoint in a range expression\n",pattern);                
                break;
            case REG_ESPACE: 
                wblprintf(LOG_WARNING,"REGEX_UTIL","Incorrect regular expresion. %s.\n\t\t\t\t\tOut of memory\n",pattern);                
                break;
            case REG_BADRPT: 
                wblprintf(LOG_WARNING,"REGEX_UTIL","Incorrect regular expresion. %s.\n\t\t\t\t\t?, * or + is not preceded by valid regular expression.\n",pattern);                
                break;
            default: 
                wblprintf(LOG_WARNING,"REGEX_UTIL","Error processing regular expression %s\n",pattern);                
                break;
        }
	regfree(re);
        free(re);
        return NULL;
    } else return re;
}

int rgx_match(const regex_t *re, const char *string){
    if(regexec(re, string, (size_t) 0, NULL, 0)) 
        return 0;
    else return 1;
}

void rgx_free(regex_t *re){
    regfree(re);
    free(re);
}
