/***************************************************************************
*
*   File    : regex_util.h
*   Purpose : Simplify the usage of GNU regex library
*
*   Author: David Ruano
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


#ifndef __REGEX_UTIL_H__
#define __REGEX_UTIL_H__
#include <regex.h>

/**
 * Compile a regular expressión
 * Return null if the regular expression has an error
 */
regex_t *rgx_compile(const char *pattern);

/**
 * True if the string matches the regular expression
 * false otherwise
 */
int rgx_match(const regex_t *re, const char *string);

/**
 * Free a regular expression
 */
void rgx_free(regex_t *re);

#endif
