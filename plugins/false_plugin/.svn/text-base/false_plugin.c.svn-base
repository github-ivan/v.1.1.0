/***************************************************************************                        
*
*   File    : false_plugin.c
*   Purpose : Implements a null plugin (never returns true)
*            
*   Author: Noemi Perez
* 
* 
*   Date    : October  9, 2010
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

#include <stdlib.h>
#include <cpluff.h>
#include "core.h"

/**
 * This plugin always return false
 */
static int false(void *_data, void *content, char *params, const char *flags){
    //printf ("Executing false.\n");
    return 0;
}

/* ------------------------------------------------------------------------
 * Exported classifier information
 * ----------------------------------------------------------------------*/

CP_EXPORT function_t es_uvigo_ei_false = { NULL, false, NULL };
