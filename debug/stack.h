/***************************************************************************
*
*   File    : stack.h
*   Purpose : Implements a stack.
*
*
*   Original Author: David Ruano Ordás
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

#ifndef STACK_H
#define	STACK_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "common_dinamic_structures.h"

#define STACK_EMPTY -2
#define STACK_OK -1
#define STACK_FAIL 0
#define ELEMENT_FOUND 1


//struct node;
struct stack;

//typedef struct node node;
typedef struct stack stack;

//typedef void *element;

//typedef int (*PFunction)(element, element);

/**
 * Inicializes the struct of the linkedlist.
 * @return the linked-list initialized.
 */
stack *newstack();

/**
 * Adds a new element to the stack
 * @param _stack the stack to insert the element.
 * @param token the data to be store in the stack.
 */
int push_item(stack *_stack, element item);

/**
 * Retrieves the first element from the stack.
 * @param _stack, the stack to retrieve the first element.
 * @param item the data to be retrieved from the stack.
 */
int peek_item(stack *_stack, element *item);

/**
 * Retrieves the first element from the stack and removes it;
 * @param _stack, the stack to retrieve the first element.
 * @param item the data to be retrieved and removed from the stack.
 */
int pop_item(stack *_stack, element *item);

int getlengthstack(stack *_stack);

extern int stack_iterate_elements(stack *_stack, PFunction f, element item);

void free_stack(stack *_stack, PFree f);

void setlengthstack(stack *_stack,int lenght);

#endif	/* LINKED_LIST_H */
