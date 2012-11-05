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

all: libeml_structure_parser.so libeml_parser_utils.a

libeml_structure_parser.so : eml_structure_parser.o eml_parser.o html.o header_parser.o
	$(CC) $(OPTSLIB) $(LIBS) -shared -W1,-soname,libeml_structure_parser.so.0 -o libeml_structure_parser.so.0 eml_structure_parser.o eml_parser.o html.o header_parser.o 
	ln -sf libeml_structure_parser.so.0 libeml_structure_parser.so
	ln -sf libeml_structure_parser.so.0 libeml_structure_parser.so.1
	
#libeml_structure_parser.a: html.o eml_parser.o header_parser.o
#	ar rcs libeml_structure_parser.a html.o eml_parser.o header_parser.o

eml_structure_parser.o:
	$(CC) $(OPTS) $(OPTSLIB) $(LIBS) -c eml_structure_parser.c -o eml_structure_parser.o

libeml_parser_utils.a: html.o eml_parser.o header_parser.o
	ar rcs libeml_parser_utils.a html.o eml_parser.o header_parser.o

eml_parser.o:
	$(CC) -static $(OPTS) $(LIBS) -c eml_parser.c -o eml_parser.o $(LIBS) $(OPTSLIB)

html.o:
	$(CC) $(LIBS) $(OPTS) $(OPTSLIB) -c html.c 

header_parser.o:
	$(CC) $(OPTS) -c header_parser.c -o header_parser.o $(LIBS) $(OPTSLIB)
	
#main: 
#	$(CC) $(LIBS) $(OPTSLIB) main.c meta_parser.o -o main $(LIBS) $(OPTSLIB)
	
clean :
	rm *.a *.o *.so *.so.? 
