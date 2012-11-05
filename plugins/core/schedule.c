/* 
 * File:   schedule.c
 * Author: drordas
 *
 * Created on 13 de octubre de 2011, 12:28
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ruleset.h"

int compare_rules_by_plugin(const void *_a, const void *_b);
/*
 * 
 */
void default_plan(void *rules){
   int i,j,k,numplugins;
   rule *tmp;
   map_t plugins;
   char *s;
   ruleset *r=(ruleset *)rules;
   
   plugins=hashmap_new();
   
   for (i=0;i<r->size;i++){
   	   if (hashmap_get(plugins,((definition *)r->rules[i].def)->plugin,(any_t *)&s)!=MAP_MISSING)
   	       hashmap_put(plugins,((definition *)r->rules[i].def)->plugin,((definition *)r->rules[i].def)->plugin);
   }
   numplugins=hashmap_length(plugins);
   hashmap_free(plugins);
   
   tmp=malloc(sizeof(rule));
   qsort(r->rules, r->size, sizeof(rule), &compare_rules_by_plugin);	

   //schedule the plugins
   for(k=1;k<numplugins;k++)
      for(i=k;i<r->size;i++){
      	  for(j=1;j<r->size/k && !strcmp(((definition *)r->rules[(i+k)%r->size].def)->plugin,((definition *)r->rules[(i+k*j)%r->size].def)->plugin);j++);
      	  if (j<r->size/k){
      	  	 memcpy(tmp,&(r->rules[(i+k)%r->size]),sizeof(rule));
      	  	 memcpy(&(r->rules[(i+k)%r->size]),&(r->rules[(i+j*k)%r->size]),sizeof(rule));
      	  	 memcpy(&(r->rules[(i+j*k)%r->size]),tmp,sizeof(rule));
          }
     }
	  
   free(tmp);

}

int compare_rules_by_plugin(const void *_a, const void *_b){
	rule *a, *b;
	a=(rule *)_a;
	b=(rule *)_b;
        
        if( (a->characteristic & NORMAL_RULE && a->characteristic & NORMAL_SCORE) &&
            (b->characteristic & NORMAL_RULE && b->characteristic & NORMAL_SCORE) )
            return strcmp(((definition *)a->def)->plugin, ((definition *)b->def)->plugin);
        else return 1;
}