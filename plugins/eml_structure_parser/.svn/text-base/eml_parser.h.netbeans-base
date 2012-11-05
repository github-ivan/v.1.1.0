/***************************************************************************
*
*   File    : eml_structure_parser.c
*   Purpose : Implements a parser of eml messages (RFC 2822)
*
*   Author: Noemi Perez, Jose Ramon Mendez
*
*
*   Date    : February  18, 2011
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

#ifndef __EML_PARSER_H__
#define	__EML_PARSER_H__

#include "hashmap.h"

#define RECEIVED_HEADER "Received"
#define CONTENT_TYPE_HEADER "Content-Type"
#define FROM_HEADER "From"
#define PARSED_HEADER "parsed_Header"

#define BODY_PART "body"
#define HEADER_PART "header"
#define FULL "full"

#define MUTEX_EML "mutex4eml"

#define RAW_ENTRY "raw"

//The rfc2822eml data structure
typedef map_t rfc2822eml;

//Mime part structure
struct mime_part;
typedef struct mime_part mime_part;

//Parse a mail (RFC2822) in the mail string and get a rfc2822eml instance
rfc2822eml parser_mail(const char *mail);

//Free a rfc2822eml instance
void free_mail(rfc2822eml eml);

//Get all the text included in a rfc2822eml instance
char *dump_text(rfc2822eml eml);

//Free all structures created for parsing issues
void freeEMLParser();

//Get header content (Except Received)
char *getHeaderContent(rfc2822eml eml, const char *header );




#endif	/* EML_PARSER_H */

