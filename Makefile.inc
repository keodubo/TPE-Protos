COMPILER=gcc

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
	# macOS: selector.c incluye <sys/signal.h>, que en Apple NO declara
	# sigaction/sigemptyset/... (viven en <signal.h>; en Linux <sys/signal.h> ya
	# reenvía allí). Forzamos el include para NO modificar el código de la cátedra.
	PLATFORM_FLAGS=-D_DARWIN_C_SOURCE -include signal.h
else
	PLATFORM_FLAGS=-D_POSIX_C_SOURCE=200809L
endif

# CFLAGS_EXTRA: knobs desde la línea de comandos, p.ej. tamaño de buffer:
#           make CFLAGS_EXTRA=-DIO_BUFFER_SIZE=8192   (ver docs/extras/buffer-sizing.md)
COMPILER_FLAGS=-std=c11 -pedantic -Wall -Wextra -g \
	$(PLATFORM_FLAGS) $(CFLAGS_EXTRA) \
	-Isrc/shared -Isrc/server -Isrc/client

LD_FLAGS=-pthread
