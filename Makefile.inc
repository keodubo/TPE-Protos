# Makefile.inc — configuración de compilación del TPE SOCKS5
#
# Basado en el provisto por la cátedra, con agregados FUNDAMENTADOS:
#   -std=c11 -pedantic : exigido por la consigna (Req. No Funcional 1: C11).
#   -Wall -Wextra      : warnings (la cátedra compila con -Wall).
#   -g                 : símbolos de depuración para gdb / valgrind.
#   $(PLATFORM_FLAGS)  : feature-test macros correctas por plataforma (ver abajo).
#   -Isrc/...          : los .c de cada binario incluyen headers de src/shared.
# Linkeo:
#   -pthread           : el selector y la resolución de DNS (M5) usan hilos POSIX.
#
# Feature-test macros por plataforma (clave para portabilidad Linux <-> macOS):
#   Linux/glibc (pampero): _POSIX_C_SOURCE=200809L expone pselect(2)/sigaction(2)/
#                          getaddrinfo(3) bajo -std=c11 (que de otro modo los oculta).
#   macOS                : _DARWIN_C_SOURCE expone el conjunto POSIX+BSD. (¡Ojo! con
#                          _POSIX_C_SOURCE a secas, macOS OCULTA sigaction/sigprocmask/
#                          pthread_kill y el build falla.)

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

COMPILER_FLAGS=-std=c11 -pedantic -Wall -Wextra -g \
	$(PLATFORM_FLAGS) \
	-Isrc/shared -Isrc/server -Isrc/client

LD_FLAGS=-pthread
