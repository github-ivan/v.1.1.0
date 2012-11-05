/***************************************************************************                        
*
*   File    : test_parser.c
*   Purpose : Used to test the flex parser
*            
*   Author: Noemi Perez, David Ruano, Jose Ramon Mendez
* 
* 
*   Date    : October  30, 2010
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

#include "list.h"
#include "lex.yy.h"
#include <string.h>
#include <stdlib.h>

int main(int argc, char *argv[]){
    /*
    lex_url_parser_init();
    flex_url_parserlex();
    printf("%s\n",lex_url_parser_get_as_string());
    lex_url_parser_flex_destroy();
    */
    printf("%s\n",lex_url_parser_parse_string("   http://xx.com   ñkjsdf lhsd \"http://ax.z\""));
    return 1;
}
