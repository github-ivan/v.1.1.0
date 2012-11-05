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

CC=cc -g -O3 -fPIC
OPTS= -c -Wall
OPTSLIB=-I../../cpluff/include -I/usr/include -I../../cpluff/include -I/usr/include -I../core -L../../cpluff/lib -L/usr/lib -L/lib -L../core 
LIBS=-lexpat -ldl -lc -lcpluff -lpthread

all: libtxt_structure_parser.so libtxt_parser_utils.a

libtxt_structure_parser.so : txt_parser.o txt_structure_parser.o
	$(CC) $(OPTSLIB) $(LIBS) -shared -W1,-soname,libtxt_structure_parser.so.0 -o libtxt_structure_parser.so.0 txt_parser.o txt_structure_parser.o
	ln -sf libtxt_structure_parser.so.0 libtxt_structure_parser.so
	ln -sf libtxt_structure_parser.so.0 libtxt_structure_parser.so.1
	
#libeml_structure_parser.a: html.o eml_parser.o header_parser.o
#	ar rcs libeml_structure_parser.a html.o eml_parser.o header_parser.o


libtxt_parser_utils.a: txt_parser.o 
	ar rcs libtxt_parser_utils.a txt_parser.o

txt_structure_parser.o:
	$(CC) $(OPTS) $(OPTSLIB) $(LIBS) -c txt_structure_parser.c -o txt_structure_parser.o


txt_parser.o:
	$(CC) -static $(OPTS) $(LIBS) -c txt_parser.c -o txt_parser.o $(LIBS) $(OPTSLIB)
#libeml_parser_utils.a: html.o eml_parser.o header_parser.o
#	ar rcs libeml_parser_utils.a html.o eml_parser.o header_parser.o
	
#main: 
#	$(CC) $(LIBS) $(OPTSLIB) main.c meta_parser.o -o main $(LIBS) $(OPTSLIB)
	
clean :
	rm *.a *.o *.so *.so.? 
