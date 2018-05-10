# Andrew Huang <bluedrum@163.com>
ifeq ($(CC),cc)
CC = gcc
endif
AR = ar rcv
ifeq ($(windir),)
EXE =
RM = rm -f
else
EXE = .exe
RM = del
endif

CFLAGS = -ffunction-sections -O3

ifneq (,$(findstring darwin,$(CROSS_COMPILE)))
    UNAME_S := Darwin
else
    UNAME_S := $(shell uname -s)
endif
ifeq ($(UNAME_S),Darwin)
    LDFLAGS += -Wl,-dead_strip
else
    LDFLAGS += -Wl,--gc-sections -s
endif

all:mkbootimg$(EXE) unpackbootimg$(EXE)

static:
	$(MAKE) LDFLAGS="$(LDFLAGS) -static"

libmincrypt.a:
	$(MAKE) -C libmincrypt

mkbootimg$(EXE):mkbootimg.o libmincrypt.a
	$(CROSS_COMPILE)$(CC) -o $@ $^ -L. -lmincrypt $(LDFLAGS)

mkbootimg.o:mkbootimg.c
	$(CROSS_COMPILE)$(CC) -o $@ $(CFLAGS) -c $< -I. -Werror

unpackbootimg$(EXE):unpackbootimg.o
	$(CROSS_COMPILE)$(CC) -o $@ $^ $(LDFLAGS)

unpackbootimg.o:unpackbootimg.c
	$(CROSS_COMPILE)$(CC) -o $@ $(CFLAGS) -c $< -Werror

clean:
	$(RM) mkbootimg unpackbootimg
	$(RM) *.a *.~ *.exe *.o
	$(MAKE) -C libmincrypt clean

