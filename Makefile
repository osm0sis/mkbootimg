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

GCC_VER_CEK := $(shell expr `gcc -dumpversion | sed -e 's/\.\([0-9][0-9]\)/\1/g' -e 's/\.\([0-9]\)/0\1/g' -e 's/^[0-9]\{3,4\}$$/&00/'` \<= 40201)
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
	$(CROSS_COMPILE)$(CC) -o $@ $(CFLAGS) -c $< $(if $(filter $(GCC_VER_CEK),1), ,-Werror)

clean:
	$(RM) mkbootimg mkbootimg-static mkbootimg.o unpackbootimg unpackbootimg-static unpackbootimg.o mkbootimg.exe mkbootimg-static.exe unpackbootimg.exe unpackbootimg-static.exe
	$(RM) libmincrypt.a Makefile.~
	make -C libmincrypt clean

