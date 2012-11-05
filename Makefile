#	LICENSING
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

CC=gcc -g -O3 -fPIC 
CFLAGS=-c -Wall
OPTS=-Wall -Icpluff/include -I/usr/lib -I/usr/lib/include -Lcpluff/lib -L/usr/lib -L/lib -Iplugins/core -Lplugins/core
LIBS=-lcpluff -lexpat -lpthread -ldl -lutils
all : libfileutils.a wb4cms wb4spam cpluff

cpluff:
	chmod +x /cpluff_source/cpluff-0.1.3/moncho_compile.sh
	./cpluff_source/cpluff-0.1.3/moncho_compile.sh

#Wirebrush4CMS filtering framework
	
wb4all:
	make -C plugins/txt_structure_parser
	make -C plugins/eml_strcuture_parser
	make -C plugins/core
	make -C plugins/false_plugin
	

wb4cms_dependences:
	make -C plugins/txt_structure_parser
	make -C plugins/eml_structure_parser
	make -C plugins/core

wb4cms: wb4cms_dependences wb4cms_main wb4cms_daemon
	make -C database
	make -C plugins/preschedule_plugin
	make -C plugins/txt_bayes_plugin
	make -C plugins/txt_pcre_regex_plugin
	make -C plugins/txt_regex_plugin
	make -C plugins/false_plugin

wb4cms_main: wb4cms.o fileutils.o
	$(CC) $(OPTS) fileutils.o wb4cms.o -o wb4cms $(LIBS) 

wb4cms.o : 
	$(CC) $(OPTS) $(LIBS) -c csa.c -o wb4cms.o

wb4cms_daemon : wb4cmsd.o fileutils.o
	$(CC) $(OPTS) $(LIBS)  fileutils.o wb4cmsd.o -o wb4cmsd $(LIBS)

wb4cmsd.o : 
	$(CC) $(OPTS) $(LIBS) $(CFLAGS) wb4spamd.c -o wb4cmsd.o

#Wirebrush4SPAM filtering framework

wb4spam_dependences:
	make -C plugins/eml_structure_parser	
	make -C plugins/core

wb4spam: wb4spam_dependences wb4spam_main wb4spam_daemon
	make -C database        
	make -C plugins/preschedule_plugin
	make -C plugins/bayes_plugin
	make -C plugins/pcre_regex_plugin
	make -C plugins/regex_plugin
	make -C plugins/spf_plugin
	make -C plugins/axl_plugin
	make -C plugins/rxl_plugin
	make -C plugins/false_plugin

wb4spam_main : wb4spam.o fileutils.o
	$(CC) $(OPTS) fileutils.o wb4spam.o -o wb4spam $(LIBS) 

wb4spam.o : 
	$(CC) $(OPTS) $(LIBS) -c csa.c -o wb4spam.o
	
wb4spam_daemon : wb4spamd.o fileutils.o
	$(CC) $(OPTS) $(LIBS)  fileutils.o wb4spamd.o -o wb4spamd $(LIBS)

wb4spamd.o : 
	$(CC) $(OPTS) $(LIBS) $(CFLAGS) wb4spamd.c -o wb4spamd.o

wb4spam_clean: 
	make clean -C plugins/eml_structure_parser
	make clean -C plugins/core
	make clean -C plugins/preschedule_plugin
	make clean -C plugins/bayes_plugin
	make clean -C plugins/pcre_regex_plugin
	make clean -C plugins/regex_plugin
	make clean -C plugins/spf_plugin
	make clean -C plugins/axl_plugin
	make clean -C plugins/rxl_plugin
	make clean -C plugins/false_plugin
	make clean -C database
	rm *.o *.a wb4spamd wb4spam
	make db_clean -C database

wb4cms_clean:
	make clean -C plugins/txt_structure_parser
	make clean -C plugins/core
	make clean -C plugins/preschedule_plugin
	make clean -C plugins/txt_bayes_plugin
	make clean -C plugins/txt_pcre_regex_plugin
	make clean -C plugins/txt_regex_plugin
	make clean -C plugins/false_plugin
	make clean -C database
	rm *.o wb4cmsd wb4cms
	make db_clean -C database

clean_all:
	make clean -C plugins/eml_structure_parser
	make clean -C plugins/txt_structure_parser
	make clean -C plugins/core
	make clean -C plugins/preschedule_plugin
	make clean -C plugins/bayes_plugin
	make clean -C plugins/pcre_regex_plugin
	make clean -C plugins/regex_plugin
	make clean -C plugins/spf_plugin
	make clean -C plugins/axl_plugin
	make clean -C plugins/rxl_plugin
	make clean -C plugins/txt_bayes_plugin
	make clean -C plugins/txt_pcre_regex_plugin
	make clean -C plugins/txt_regex_plugin	
	make clean -C plugins/false_plugin
	make clean -C database
	rm *.o wb4spamd wb4spam wb4cmsd wb4cms
	make db_clean -C database

	
libfileutils.a: fileutils.o
	ar rcs libfileutils.a fileutils.o

fileutils.o:
	$(CC) $(CFLAGS) fileutils.c -o fileutils.o

updateldcache: 
	if test "$(cat /etc/ld.so.conf.d/* | grep "cpluff")" = "" ; then \
	  echo "`pwd`/cpluff/lib" > /etc/ld.so.conf.d/cpluff.conf ;\
	fi
	ldconfig
