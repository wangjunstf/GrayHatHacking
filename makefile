CFLAGS = -ggdb -O0 -fno-stack-protector -zexecstack -mpreferred-stack-boundary=2 -m32 

src = $(wildcard *.c)
target = $(patsubst %.c, %, ${src})

.PHONY: all clean

%.o:%.c
	gcc ${CFLAGS} -c -o $@
%:%.o
	gcc ${LDFLAGS} -o $@

all: ${target}

clean:
	rm -f ${target}
