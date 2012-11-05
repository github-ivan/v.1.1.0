/* 
 * File:   learn_cms_bayes.h
 * Author: drordas
 *
 * Created on 5 de marzo de 2012, 17:22
 */

#ifndef _LEARN_CMS_BAYES_H_
#define	_LEARN_CMS_BAYES_H_

map_t cms_tokenizebody(char * email);

/* Loads the emails contained in a path and stores its tokens in a berkeley database.*/
void cms_load_directory_mail(char *directory, char *db_path, int type);

#endif	/* LEARN_CMS_BAYES_H */

