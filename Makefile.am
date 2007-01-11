APXS = @APXS@ 
SHAREDFLAG = @SHAREDFLAG@ 
DEF= @DEFS@ 
INC = @CPPFLAGS@ 
LIB = @LIBS@ 
AM_CFLAGS = @CFLAGS@
MODULESOURCES = mod_defensible.c 

lib_LTLIBRARIES = mod_defensible.la 

mod_defensible_la_SOURCES = $(MODULESOURCES) 
mod_defensible_la_LDFLAGS = -module `${APXS} -q LDFLAGS_SHLIB` 
mod_defensible_la_CPPFLAGS = -I`${APXS} -q INCLUDEDIR` 
mod_defensible_la_CFLAGS = -W -Wall `${APXS} -q CFLAGS CFLAGS_SHLIB` 
CC = `${APXS} -q CC` 
	   
# install the DSO file into the Apache installation 
# and activate it in the Apache configuration 
install: all
	$(APXS) -i -a -n 'defensible' .libs/mod_defensible.so 
