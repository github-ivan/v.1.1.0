/***************************************************************************
*
*   File    : pcre_regex_util.h
*   Purpose : Simplify the usage of pcre_regex functionality
*
*   Author: David Ruano
*
*
*   Date    : December  9, 2010
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

#ifndef PCRE_REGEX_UTIL_H
#define	PCRE_REGEX_UTIL_H

#include <pcre.h>

pcre *pcregex_compile(const char *pattern);

int pcregex_match(const pcre *reg, const char *string);

void pcregex_free(pcre *reg);

#endif	/* PCRE_REGEX_UTIL_H */

