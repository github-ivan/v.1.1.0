/***************************************************************************
*
*   File    : fileutils.c
*   Purpose : Implements librari for reading emls.
*
*
*   Original Author: David Ruano Ordás, Moncho Méndez Reboredo.
*
*
*   Date    : February  14, 2010
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
#include "fileutils.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>


int ae_load_eml_to_memory(const char *filename, char **result)
{ 
    int size = 0;
    
    FILE *f = fopen(filename, "rb");
    if (f == NULL){
        *result = NULL;
        return OPEN_ERROR;
    }
    fseek(f, 0, SEEK_END);
    size = ftell(f);
    fseek(f, 0, SEEK_SET);
    *result = (char *)malloc(size+1);
    if (size != fread(*result, sizeof(char), size, f)) {
        free(*result);
        return READ_FAIL;
    }

    fclose(f);
    (*result)[size] = '\0';
    return size;
}
