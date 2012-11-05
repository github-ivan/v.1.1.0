#LICENSING
#
#       This file is part of WireBrush for Spam project (WB4Spam).
#
#       WB4Spam: An ANSI C is an open source, highly extensible, high performance and 
#       multithread spam filtering platform. It takes concepts from SpamAssassin project
#       improving distinct issues.
#
#       Copyright (C) 2010, by Sing Research Group (http://sing.ei.uvigo.es)
#
#       Wirebrush for Spam is free software; you can redistribute it and/or
#       modify it under the terms of the GNU Lesser General Public License as
#       published by the Free Software Foundation; either version 3 of the
#       License, or (at your option) any later version.
#
#       Wirebrush for Spam is distributed in the hope that it will be useful,
#       but WITHOUT ANY WARRANTY; without even the implied warranty of
#       MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser
#       General Public License for more details.
#
#       You should have received a copy of the GNU Lesser General Public License
#       along with this program.  If not, see <http://www.gnu.org/licenses/>.

CC=cc -fPIC -O3 -g
CFLAGS=-c -Wall
OPTSLIB=-I/usr/include -I../plugins/core -I../plugins/eml_structure_parser -I../plugins/txt_structure_parser -I.. -I/usr/lib -I../ -I../plugins/spam_hunting_plugin
LIBS=-L/usr/lib -L. -L../plugins/core -L../plugins/eml_structure_parser -L../plugins/txt_structure_parser -L.. -L../ -L../plugins/spam_hunting_plugin -leml_parser_utils -ltxt_parser_utils -lutils -lfileutils -ldb -lpthread

all : wb4spaml learn_bayes_utils.a learn_spamhunting.a learn_axl.a 
#axllearn	
#shlearn

wb4spaml :sha1.o learn_bayes_utils.o learn_spamhunting.o learn_spam_bayes.o learn_cms_bayes.o learn_axl.o tokenize.o db_utils.o
	$(CC) learn_bayes_utils.o learn_spamhunting.o learn_spam_bayes.o learn_cms_bayes.o sha1.o learn_axl.o tokenize.o db_utils.o wblearn.c $(OPTSLIB) $(LIBS) -o wb4spaml
	cp wb4spaml wb4cmsl

#shlearn : sha1.o learn_spamhunting.o tokenize.o db_utils.o
#$(CC) learn_spamhunting.o sha1.o tokenize.o db_utils.o shlearn.c $(OPTSLIB) $(LIBS) -o shlearn
	
#axllearn : learn_axl.o sha1.o db_utils.o
#	$(CC) learn_axl.o sha1.o  db_utils.o axllearn.c $(OPTSLIB) $(LIBS) -o axllearn
	
learn_spamhunting.o: 
	$(CC) $(CFLAGS) $(OPTSLIB) $(LIBS) learn_spamhunting.c -o learn_spamhunting.o

learn_spamhunting.a: learn_spamhunting.o tokenize.o sha1.o db_utils.o
	ar rcs liblearn_spamhunting.a tokenize.o learn_spamhunting.o sha1.o db_utils.o

learn_bayes_utils.o:
	$(CC) $(CFLAGS) $(OPTSLIB) $(LIBS) learn_bayes_utils.c -o learn_bayes_utils.o	

learn_bayes_utils.a : learn_spam_bayes.o learn_cms_bayes.o learn_bayes_utils.o tokenize.o sha1.o db_utils.o
	ar rcs liblearn_bayes_utils.a learn_spam_bayes.o learn_cms_bayes.o tokenize.o learn_bayes_utils.o sha1.o db_utils.o

learn_axl.a : learn_axl.o sha1.o db_utils.o
	ar rcs liblearn_axl.a learn_axl.o sha1.o db_utils.o

learn_spam_bayes.o : 
	$(CC) $(CFLAGS) $(OPTSLIB) $(LIBS) learn_spam_bayes.c -o learn_spam_bayes.o
	
learn_cms_bayes.o : 
	$(CC) $(CFLAGS) $(OPTSLIB) $(LIBS) learn_cms_bayes.c -o learn_cms_bayes.o

learn_axl.o : 
	$(CC) $(CFLAGS) $(OPTSLIB) $(LIBS) learn_axl.c -o learn_axl.o

sha1.o:
	$(CC) $(CFLAGS) sha1.c -o sha1.o

tokenize.o:
	$(CC) $(OPTSLIB) $(CFLAGS) tokenize.c -o tokenize.o
	
db_utils.o:
	$(CC) $(OPTSLIB) $(CFLAGS) db_utils.c -o db_utils.o

clean : 
	rm *.a *.o wb4spaml wb4cmsl

db_clean:
	rm __* *.db