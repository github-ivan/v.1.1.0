/***************************************************************************                        
*
*   File    : core.h
*   Purpose : Implements the core filtering system for WB4Spam
*            
*            
*   Author: David Ruano
* 
* 
*   Date    : April 13, 2011
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

#ifndef __CORE_H__
#define __CORE_H__

#include "iniparser.h"

//#define rule_config_path "./filter/"
//#define file_config_path "config.ini"

#define cms_rule_config_path "./wb4cms_filter/"
#define cms_file_config_path "wb4cms_config.ini"
#define spam_rule_config_path "./wb4spam_filter/"
#define spam_file_config_path "wb4spam_config.ini"


/*Sets the debug mode
 * 1 - ONLY SHOW INFO MESSAGES.
 * 2 - ONLY SHOW WARNINGS MESSAGES.
 * 3 - SHOW INFO + WARNINGS MESSAGES.
 */
#define DEBUG_MODE 1

#define CMS_FILTER 1
#define SPAM_FILTER 0
#define UNDEF_FILTER -1

#define DEFINITIVE_ENABLE 0
#define LAZY_ENABLE 1

/**
 * A function that estimates if mail is spam or not. If function stimates
 * true then returns a number great than 0. Otherwise it returns 0.
 *
 * @param data runtime data of the function
 * @param content the email contents
 * @return an estimation of the email is spam or ham
 */
typedef int (*function_func_t)(void *data, void *content, char *params, const char *flags);//, int parserType); //const char * content antes

typedef void (*config_func_t) (void *_data, ini_file *config_file);

/** A short hand typedef for function_t structure */
typedef struct function_t function_t;

/**
 * A container for function information.
 */
struct function_t {
	
	/** Function specific runtime data */
	void *data;
	
	/** The function */
	function_func_t function;

        config_func_t conf_function;        
};

/**
 * A function that parses e-mails. It uses the content of email
 * and returns some parts of the content depending of the parser
 *
 * @param data runtime data of the parser
 * @param content the email contents
 * @return a pointer.
 */
typedef void *(*parser_func_t)(void *data, const char *content); //const char * content

typedef void (*free_func_t)(void *data); //const char * content

/** A short hand typedef for parser_t structure */
typedef struct parser_t parser_t;

/**
 * A container for parser information.
 */
struct parser_t {

        /** Parser specific runtime data */
        void *data;

        /** The parser */
        parser_func_t function;
        
        /** The parser data */
        free_func_t free_parser_data;
};

/**
 * An EventHandler is a function that listen for spam and message classifications
 * Every time a message is classified, the core invokes all event handlers available
 * in order to notify the classification
 * 
 * @param data runtime data of the parser
 * @param content the email contents
 * @param isspam a flat active when message is spam (0 for ham messages)
 * @return void
 */
typedef void (*eventhandler_func_t)(void *_data, void *_content, const int isspam);

/** A short hand typedef for eventhandler_t structure */
typedef struct eventhandler_t eventhandler_t;

/**
 * A container for eventhandlers information.
 */
struct eventhandler_t {

        /** Event handler specific runtime data */
        void *data;

        /** The event handler */
        eventhandler_func_t function;

        /**the parsed required for the eventhandler*/
        char *parser_name;
};

/**
 * An Preschedulers is a function that allows to planificate the loaded rules in order to
 * optimize the filter execution.
 * 
 * @param data runtime data of the eventhandlers
 * @param ruleset rules loaded from de *cf files.
 * @return the rules planificated.
 */
typedef void (*prescheduler_func_t)(void *_data, void *_rules);

/** A short hand typedef for eventhandler_t structure */
typedef struct prescheduler_t prescheduler_t;

/**
 * A container for preschedulers information.
 */
struct prescheduler_t {

        /** Event handler specific runtime data */
        void *data;

        /** The event handler */
        prescheduler_func_t function;

        /**the parsed required for the eventhandler*/
        char *prescheduler_name;
};

#endif /*CORE_H_*/