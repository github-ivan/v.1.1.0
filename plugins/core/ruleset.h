/***************************************************************************                        
*
*   File    : ruleset.h
*   Purpose : Implements a ruleset (set of rules) for filtering
*            
*            
*   Original Author: Ivan Paz, Jose Ramon Mendez (from Grindstone project)
*   Has been widelly modifyed since them
* 
*   Memory improvements, modifications, inclusion of new fields
*       and functions: David Ruano, Noemi Perez, Jose Ramon Mendez
* 
*   Date    : October  14, 2010
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

#ifndef __RULESET_H__
#define __RULESET_H__
#include "hashmap.h"
#include "list_files.h"
#include "core.h"
#include "vector.h"

/* Implementation of a SpamAssassinRuleset
   @author Jose R. Mendez Reboredo
*/

//You should use pointers to ruleset type

/**
 * Struct for the rule definion. Includes the function name, the params
 * passed to function and a pointer to the real function implementation
 * in order to achieve better performance on runtime
 */

/**
 * A typedef for rule in order to get manipulation simple
 */

#define META_RULE 1<<1
#define NORMAL_RULE 1<<3
#define DEFINITIVE_SCORE 1<<4
#define NORMAL_SCORE 1<<5
#define NOT_NUMERIC_SCORE -1

#define VALID 0
#define INVALID 1

struct definition {
    char *name;
    char *param;
    function_t *pointer; //Pointer to the function.
    char *tflags; //function flags.
    char *plugin; //The function plugin
};

typedef struct definition definition;

/**
 * Struct for parser definition. Includes the parser name, and a 
 * pointer to the real parser in order to achieve better performance on
 * runtime
 */
struct parser{
    char *parserName;
    parser_t *parserPointer;
    int parser_type;
};

typedef struct parser parser;

struct score_intervals{
    float positive;
    float negative;
};

typedef struct score_intervals score_intervals;

struct meta_info {
    char *expresion;
    vector *dependant_rules;
    short status;
};

typedef struct meta_info meta_definition;

/**
 * Struct that contains a rule definition. The rule include the name, 
 * the associated score, the definition (in a definition struct), the
 * parser needed (in a parser struct) and the rule description*/
struct rule {
   char *rulename;  //The name of the rule
   void *score;   //The score
   //definition *def; // Definition of the rule {name and params}
   void *def; // Definition of the rule {name and params}
   parser *par; //The parser needed
   char *description; //The rule description
   map_t target_domain; //The target domain flag.
   short characteristic;
};

typedef struct rule rule;

/**
 * A ruleset structure. Handles set of rules (struct rule) and the
 * required_score paramenter that stands for the minimun score for 
 * classify a message as spam
 */

struct schedule_data_t{
   int end_meta;
   int end_definitive;
   int begin_normal;
};
//
typedef struct schedule_data_t schedule_data_t;

struct ruleset {
     float required; //The required score
     //stop_score *stop; //The stop score
     score_intervals *intervals;
     
     rule *rules; //The rules
     map_t map; //A map String->Int to lookup rule number from rule name
     map_t meta_map;
     map_t dependant_map;
     
     //rule *def_rules; //Definitive rules.
     int meta_size;
     int def_size;
     int size;  //The size of the map
     schedule_data_t *sdata_t;
};

typedef struct ruleset ruleset;


//Achieve the score for a rule
//float get_rule_score(const ruleset *rules, char* rulename);

//Achieve the socre for a rule
void *get_rule_score(const ruleset *rules, int ruleno);

int has_zero_score(const ruleset *rules, int ruleno);

//char *get_definitive_score(const ruleset *rules, int ruleno);

float get_meta_score(const ruleset *rules, int metano);

//Find the index of a rule
int get_rule_index(const ruleset *rules, char* rulename);


short get_rule_characteristic(const ruleset *rules, const int ruleno);

//int get_def_index(const ruleset *rules, char* rulename);

int get_meta_index(const ruleset *rules, char* rulename);

//Load a ruleset from a file
ruleset *load_ruleset(const filelist* files, int program_mode);

//Write a ruleset using standard output
void write_ruleset(const char* filename, const ruleset *rules);

//Write a ruleset using standard output
void out_ruleset(const ruleset *rules);

//Retrieve the number of rules
int count_rules(const ruleset *rules);

//Retrieve the number of rules
int count_definitive_rules(const ruleset *rules);

//Retrieve the number of meta rules
int count_meta_rules(const ruleset *rules);

//Mutate the ruleset (evolutionary computation)
ruleset *mutate(const ruleset *rulesin);

//Make a random merge of two rulesets (used for evolutionary computation)
ruleset *combine(const ruleset *rules1, const ruleset *rules2);

//Set required score
void set_required_score(ruleset *rules, float required);

//Get the required score
float get_required_score(const ruleset *rules);

//Set upper stop score
void set_upper_score(ruleset *rules, float upper);

//Set lower stop score
void set_lower_score(ruleset *rules, float lower);

//Get the lower stop score. For default filter evaluation
float get_lower_score(const ruleset *rules);

//Get the upper stop score. For default filter evaluation
float get_upper_score(const ruleset *rules);

//Get the sum of the positive scores. For smart filter evaluation
float get_positive_score(const ruleset *rules);

//Get the sum of the negativee scores. For smart filter evaluation
float get_negative_score(const ruleset *rules);

char * get_rulename(const ruleset *rules,const int ruleno);

char * get_metaname(const ruleset *rules,const int ruleno);

definition *get_definition(const ruleset *rules,const int ruleno);

char *get_definition_name(const ruleset *rules,const int ruleno);

char *get_definition_param(const ruleset *rules,const int ruleno);

vector *get_dependant_rules(const ruleset *rules, const int ruleno);

function_t *get_definition_pointer(const ruleset *rules,const int ruleno);

//Get the definition plugin for the rule.
char *get_definition_plugin(ruleset *rules, const int ruleno);

//Get the rule flags.
char *get_tflags(const ruleset *rules,const int ruleno);

//Get the rule parser
parser *get_parser(const ruleset *rules, const int ruleno);

//Get the rule parser name
char *get_parser_name(const ruleset *rules,const int ruleno);

//Get the rule parser type
//int get_parser_type(const ruleset *rules, const int ruleno);

//Get the rule domain restriction
map_t get_rule_domain(const ruleset *rules,const int ruleno);

map_t get_meta_domain(const ruleset *rules,const int ruleno);

char *get_meta_definition(const ruleset *rules,const int ruleno);

//Get the rule parser pointer
parser_t *get_parser_pointer(const ruleset *rules,const int ruleno);

void set_debug_mode(int debug);

//Get the name of the rule
void set_rulename(ruleset *rules, const int ruleno, const char* rulename);

//Set a definition for the definitive rule.
void set_def_definition(ruleset *rules, const int ruleno, const char *defName, const char * defParam);

//Set a definition for the rule.
void set_definition(ruleset *rules, const int ruleno, const char *defName, const char * defParam);

//Set a definition name for the rule.
void set_definition_name(ruleset *rules, const int ruleno, const char * newName);

//Set a definition param for the rule.
void set_definition_param(ruleset *rules, const int ruleno, const char * newParam);

//Set a definition pointer for the rule.
void set_definition_pointer(ruleset *rules, const int ruleno, function_t *newPointer);

//Set the definition plugin for the rule.
void set_definition_plugin(ruleset *rules, const int ruleno, const char *newPlugin);

//Set newFlags for the rule.
void set_tflags(ruleset *rules, const int ruleno, const char *newFlags);

//Set new parser for the definitive rule.
void set_def_parser(ruleset *rules,const int ruleno, const char *parserName );
//Set new parser for the rule.
void set_parser(ruleset *rules,const int ruleno, const char *parserName);//, int parserType);

//Set new parser name for the rule.
void set_parser_name(ruleset *rules,const int ruleno,const char *newParserName);

//Set new parser pointer for the rule
void set_parser_pointer(ruleset *rules,int ruleno, parser_t *newParserPointer);

//Set the description of the rule
void set_description(ruleset *rules, int ruleno, const char* desc);

//void set_meta_expression(ruleset *rules, int ruleno, const char* exp);

void set_meta_definition(ruleset *rules, const int ruleno, char *expresion);

//Get the description of the rule
char *get_description(const ruleset *rules,const int ruleno);

int is_dependant_rule(ruleset *rules,const int ruleno);

//char *get_meta_expression(const ruleset *rules, int ruleno);

short is_valid_meta(ruleset *rules, const int ruleno);

//Free memory used by a ruleset
void ruleset_free(ruleset *r);

//Preshedule rules
void preschedule(ruleset *r);


int free_vector_element(element data);

#endif