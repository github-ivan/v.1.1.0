/* 
 * File:   probabilities.h
 * Author: noemi
 *
 * Created on 12 de enero de 2011, 17:05
 */

#ifndef PROBABILITIES_H__
#define	PROBABILITIES_H__

#define NOT_INFO_AVAILABLE -2

#include "learn_bayes_utils.h"

struct dbinfo{
    tokendata *magic_token;
    DB *dbp;
};

typedef struct dbinfo dbinfo;

double prob_token (char *token,dbinfo *info);//int ns, int nn, int tok_spam, int tok_ham);

#endif	/* PROBABILITIES_H */

