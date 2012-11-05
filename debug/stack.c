/****************************************************************
*
*   File    : stack.c
*   Purpose : Implements a stack for storing data.
*
*
*   Author  : David Ruano Ordás
*
*
*   Date    : February  14, 2011
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
#include <stdio.h>
#include <string.h>
#include "logger.h"
#include "stack.h"

/*
 * Struct witch stores the info of each node of the stack
 */

//typedef struct node node;

/*
struct node{
   element value;
   struct node *next;
};
*/
/*
 * Struct which stores the pointers to the beginning and end of the linkedlist.
 * Also stores the lenght of the linkedlist.
 */

struct stack{
    node *header;
    int lenght;
};


/**
 * Inicializes the struct of the linkedlist.
 * @return the linked-list initialized.
 */

stack *newstack(){

    stack *newstack = (stack *) malloc(sizeof(stack));

    if(newstack==NULL){
        wblprintf(LOG_CRITICAL,"STACK","Not enought memory");
        exit(1);
    }
    newstack->header=NULL;
    newstack->lenght=0;

    return newstack;
}

/**
 * Adds a new element to the stack
 * @param _stack the stack to insert the element.
 * @param token the data to be store in the stack.
 */
int push_item(stack *_stack, element item) {

    node *new;
    //Reservamos memoria para esta estructura

    if ((new = (node *) malloc(sizeof(node)))) {

        _stack->lenght++;
        new->value=item;

        if(_stack->header==NULL){
            new->next=NULL;
            _stack->header=new;
        }
        else{
            new->next=_stack->header;
            _stack->header=new;
        }
        return STACK_OK;

    }
    else return STACK_FAIL;

        
}

/**
 * Retrieves the first element from the stack.
 * @param _stack, the stack to retrieve the first element.
 * @param item the data to be retrieved from the stack.
 */
int peek_item(stack *_stack, element *item){

    if(_stack->lenght==0){
        *item=NULL;
        return STACK_EMPTY;
    }
    if(_stack->lenght==1){
        *item=_stack->header->value;
        return ELEMENT_FOUND;
    }

    *item=_stack->header->value;
    
    return ELEMENT_FOUND;
}

/**
 * Retrieves the first element from the stack and removes it;
 * @param _stack, the stack to retrieve the first element.
 * @param item the data to be retrieved and removed from the stack.
 */
int pop_item(stack *_stack, element *item){

    if(_stack->lenght<=0){
        *item=NULL;
        return STACK_EMPTY;
    }
    if(_stack->lenght==1){
        *item=_stack->header->value;
        free(_stack->header);
        _stack->header=NULL;
        _stack->lenght--;
        return ELEMENT_FOUND;
    }

    node *aux;
    aux=_stack->header;
    _stack->header=aux->next;
    *item=aux->value;
    _stack->lenght--;
    free(aux);
    return ELEMENT_FOUND;
}

/**
 * Gets the lenght of the stack
 * @param _stack the stack which wants to know the lenght
 * @return the length of the stack
 */
int getlengthstack(stack *_stack){
    if(_stack!=NULL)
        return _stack->lenght;
    else return 0;
}

void setlengthstack(stack *_stack,int lenght){
    _stack->lenght=lenght;
}

extern int stack_iterate_elements(stack *_stack, PFunction f, element item){

    int i;
    node *aux=_stack->header;

    if(_stack->lenght<=0 || _stack->header==NULL)
        return STACK_EMPTY;

    for (i=0;i<_stack->lenght;i++){
        element data= (element)(aux->value);
        int status = f(item, data);
        if (status != STACK_OK) {
            return status;
        }
        if(aux->next!=NULL) aux=aux->next;
    }
    return STACK_OK;

}

void free_stack(stack *_stack, PFree f){
    int i=0;
    node *aux=_stack->header;
    node *temp;
    //printf("LLAMO A FREE_STACK\n");
    for(i=0;i<_stack->lenght;i++){
        if(aux!=NULL){
            void *data=(void *)(aux->value);
            if(data!=NULL)
                f(data);
            if(aux->next!=NULL){
                temp=aux;
                aux=aux->next;
                free(temp);
            }
            else free(aux);
        }
    }
    free(_stack);
    //_stack->header=NULL;
    //_stack->lenght=0;
}

/*
int print_item(element item, element data){
    printf("VALOR DEL DATO ES %i\n",*(int *)data);
    return STACK_OK;
}


int free_stack_item(element data){
    printf("LIBERANDO.....%d\n",*(int *)data);
    free((int *)data);
    return STACK_OK;
}

int main(){

    stack *pila=newstack();
    int i;
    int *data;
    element res;
    
    for(i=0;i<10;i++){
        data=(int *)malloc(sizeof(int));
        *data=i;
        printf("[%d]-Dato: %d\n",i,*data);
        push_item(pila,data);
    }

    printf("TOTAL DE ELEMENTOS DE LA PILA: %d\n",getlengthstack(pila));


    printf("USANDO EL PEEK\n");
    for(i=0;i<10;i++){
        peek_item(pila,(element *)&res);
        printf("[%d]-Dato: %d\n",i,*(int *)res);
    }

    printf("USANDO EL POP\n");
    for(i=0;i<10;i++){
        printf("Sol: %d\n",pop_item(pila,(element *)&res));
        printf("[%d]-Dato: %d\n",i,*(int *)res);
    }

    printf("VACIANDO PILA\n");
    free_stack(pila, &free_stack_item);
    

    return 1;
}

*/