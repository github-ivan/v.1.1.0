/* 
 * File:   caca.c
 * Author: drordas
 *
 * Created on 13 de marzo de 2012, 13:26
 */

#include <stdio.h>
#include <stdlib.h>

#define META_RULE 1<<2
#define NORMAL_RULE 1<<3
#define DEFINITIVE_SCORE 1<<4
#define NORMAL_SCORE 1<<5

/*
 * 
 */
int main(int argc, char** argv) {

    int flags;
    
    flags |= META_RULE;
    
    printf("META_RULE: %d\n",flags);
    
    flags |= NORMAL_RULE;
    
    printf("META_RULE | NORMAL_RULE: %d\n",flags);
    
    flags |= DEFINITIVE_SCORE;
    
    printf("META_RULE | NORMAL_RULE | DEFINITIVE_SCORE: %d\n",flags);
    
    if(flags & NORMAL_SCORE)
        printf("TIENE NORMAL SCORE\n");
    
}

