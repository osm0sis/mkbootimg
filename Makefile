# Andrew Huang <bluedrum@163.com>
CC = gcc
AR = ar rcv
ifeq ($(windir),)
EXE =
RM = rm -f
else
EXE = .exe
RM = del
endif

CFLAGS = -ffunction-sections -O3
LDFLAGS = -Wl

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
    LDFLAGS += -dead_strip
else
    LDFLAGS += --gc-sections
endif

all:libmincrypt.a mkbootimg$(EXE) unpackbootimg$(EXE)

static:libmincrypt.a mkbootimg-static$(EXE) unpackbootimg-static$(EXE)

libmincrypt.a:
	make -C libmincrypt

mkbootimg$(EXE):mkbootimg.o
	$(CROSS_COMPILE)$(CC) -o $@ $^ -L. -lmincrypt $(LDFLAGS) -s

mkbootimg-static$(EXE):mkbootimg.o
	$(CROSS_COMPILE)$(CC) -o $@ $^ -L. -lmincrypt $(LDFLAGS) -static -s

mkbootimg.o:mkbootimg.c
	$(CROSS_COMPILE)$(CC) -o $@ $(CFLAGS) -c $< -I. -Werror

unpackbootimg$(EXE):unpackbootimg.o
	$(CROSS_COMPILE)$(CC) -o $@ $^ $(LDFLAGS) -s

unpackbootimg-static$(EXE):unpackbootimg.o
	$(CROSS_COMPILE)$(CC) -o $@ $^ $(LDFLAGS) -static -s

unpackbootimg.o:unpackbootimg.c
	$(CROSS_COMPILE)$(CC) -o $@ $(CFLAGS) -c $< $(if $(filter $(UNAME_S),Darwin), ,-Werror)

clean:
	$(RM) mkbootimg mkbootimg-static mkbootimg.o unpackbootimg unpackbootimg-static unpackbootimg.o mkbootimg.exe mkbootimg-static.exe unpackbootimg.exe unpackbootimg-static.exe
	$(RM) libmincrypt.a Makefile.~
	make -C libmincrypt clean
