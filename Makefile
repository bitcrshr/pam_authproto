# Make file for the pam_authproto module

SECUREDIR =/lib/security
INSTALL   = install

CFLAGS = -O2 -g -Wall
#-Wall -Wformat-security -Wbad-function-cast -Wcast-align \
         -Wcast-qual -Wmissing-declarations -Wmissing-prototypes \
         -Wpointer-arith -Wreturn-type -Wstrict-prototypes -Wwrite-strings \
         -Winline -Wshadow
CPPFLAGS = -DPIC -D_GNU_SOURCE
CFLAGS += -fPIC
# -fvisibility=hidden
LDFLAGS += -shared -Wl,--as-needed -Wl,--no-undefined -Wl,-O1 \
           -Wl,-soname -Wl,pam_authproto.so

MODULE = pam_authproto.so
LDLIBS = -lpam
LIBOBJ = pam_authproto.o


all: $(MODULE)

$(MODULE): $(LIBOBJ)
	$(CC) $(LDFLAGS) $(LIBOBJ) $(LDLIBS) -o $@


pam_authproto.o: pam_authproto.c
	$(CC) -c $(CPPFLAGS) $(CFLAGS) $< -o $@

install: $(MODULE)
	$(INSTALL) -m 0755 -d $(DESTDIR)$(SECUREDIR)
	$(INSTALL) -m 0755 $(MODULE) $(DESTDIR)$(SECUREDIR)

clean:
	$(RM) -f *.o *.so
