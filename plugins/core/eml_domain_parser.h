/* 
 * File:   domain_parser.h
 * Author: david
 *
 * Created on 28 de junio de 2011, 18:31
 */

#ifndef _DOMAIN_PARSER_H_
#define	_DOMAIN_PARSER_H_

#include "hashmap.h"

map_t get_eml_domains(char *domains);
int exist_eml_domain(map_t domains, char *key);
void free_eml_domains(map_t domains);
void print_eml_domains(map_t domains);
char *get_eml_to_field(map_t eml);

#endif

