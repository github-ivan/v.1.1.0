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
FLEXPREFFIX=flex_url_parser
FLEX=flex --prefix=$(FLEXPREFFIX)
OPTS=-Wall -O2 -g -fPIC -I../../cpluff/include -I/usr/include -I../core 
OPTSLIB=-shared -W1,-soname,liburl_parser.so.0 -I../../cpluff/include -I/usr/include -I ../core -L../../cpluff/lib -L/usr/lib -L/lib -L../core
LIBDIRS=-L../../cpluff/lib -L/usr/lib -L/lib -L../core
LIBS=-lexpat -ldl -lc -lcpluff

all: test_parser liburl_parser.so

test_parser : lex.yy.h 
	$(CC) $(OPTS) $(LIBDIRS) -o test_parser test_parser.c $(LIBS)

liburl_parser.so : url_parser.o lex.yy.h
	$(CC) $(OPTSLIB) -o liburl_parser.so.0 url_parser.o $(LIBS)
	ln -sf liburl_parser.so.0 liburl_parser.so
	ln -sf liburl_parser.so.0 liburl_parser.so.1

url_parser.o : lex.yy.h
	$(CC) $(OPTS) $(LIBS) -c url_parser.c

lex.yy.h : 
	$(FLEX) -CF -Ce -olex.yy.h url.flex

clean : 
	rm *.o *.so *.so.? lex.yy.h test_parser
