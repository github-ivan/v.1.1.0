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

CC=cc
OPTS=-Wall -O2 -g -fPIC -I../../cpluff/include -I/usr/include -I../core -I../eml_structure_parser
OPTSLIB=-shared -W1,-soname,libregex_plugin.so.0 -I../../cpluff/include -I/usr/include -I../core -I../eml_structure_parser -L../../cpluff/lib -L/usr/lib -L/lib -L../core -L../eml_structure_parser
LIBS=-lcpluff -lexpat -lpthread -ldl -lc 
LIBDIRS=-L../../cpluff/lib -L/usr/lib -L/lib -L../core -L../eml_structure_parser

all: libregex_plugin.so

libregex_plugin.so : regex_plugin.o regex_util.o
	gcc $(OPTSLIB) -o libregex_plugin.so.0 regex_plugin.o regex_util.o $(LIBS)
	ln -sf libregex_plugin.so.0 libregex_plugin.so
	ln -sf libregex_plugin.so.0 libregex_plugin.so.1

regex_util.o :
	gcc $(OPTS) $(LIBS) -c regex_util.c $(LIBDIRS)

regex_plugin.o :
	gcc $(OPTS) $(LIBS) -c regex_plugin.c $(LIBDIRS)

clean : 
	rm *.o *.so *.so.?
