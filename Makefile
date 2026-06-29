include ./Makefile.inc

SERVER_SOURCES=$(wildcard src/server/*.c)
CLIENT_SOURCES=$(wildcard src/client/*.c)
SHARED_SOURCES=$(wildcard src/shared/*.c)

SERVER_OBJECTS=$(SERVER_SOURCES:src/%.c=obj/%.o)
CLIENT_OBJECTS=$(CLIENT_SOURCES:src/%.c=obj/%.o)
SHARED_OBJECTS=$(SHARED_SOURCES:src/%.c=obj/%.o)
DEP_FILES=$(SERVER_OBJECTS:.o=.d) $(CLIENT_OBJECTS:.o=.d) $(SHARED_OBJECTS:.o=.d)

OUTPUT_FOLDER=./bin
OBJECTS_FOLDER=./obj

SERVER_OUTPUT_FILE=$(OUTPUT_FOLDER)/server
CLIENT_OUTPUT_FILE=$(OUTPUT_FOLDER)/client

all: client server
server: $(SERVER_OUTPUT_FILE)
client: $(CLIENT_OUTPUT_FILE)

$(SERVER_OUTPUT_FILE): $(SERVER_OBJECTS) $(SHARED_OBJECTS)
	mkdir -p $(OUTPUT_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) $(LD_FLAGS) $(SERVER_OBJECTS) $(SHARED_OBJECTS) -o $(SERVER_OUTPUT_FILE)

$(CLIENT_OUTPUT_FILE): $(CLIENT_OBJECTS) $(SHARED_OBJECTS)
	mkdir -p $(OUTPUT_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) $(LD_FLAGS) $(CLIENT_OBJECTS) $(SHARED_OBJECTS) -o $(CLIENT_OUTPUT_FILE)

obj/%.o: src/%.c
	mkdir -p $(OBJECTS_FOLDER)/server
	mkdir -p $(OBJECTS_FOLDER)/client
	mkdir -p $(OBJECTS_FOLDER)/shared
	$(COMPILER) $(COMPILER_FLAGS) -MMD -MP -c $< -o $@

-include $(DEP_FILES)

# tests unitarios (harness plano en C, sin libcheck)
TEST_HELLO=$(OUTPUT_FOLDER)/hello_test
TEST_DBG=$(OUTPUT_FOLDER)/dbg_test
TEST_AUTH=$(OUTPUT_FOLDER)/auth_test
TEST_USERS=$(OUTPUT_FOLDER)/users_test
TEST_REQUEST=$(OUTPUT_FOLDER)/request_test
TEST_CONNECT=$(OUTPUT_FOLDER)/connect_test
TEST_COPY=$(OUTPUT_FOLDER)/copy_test
TEST_NETUTILS=$(OUTPUT_FOLDER)/netutils_test
TEST_SELECTOR_BLOCK=$(OUTPUT_FOLDER)/selector_block_test
TEST_METRICS=$(OUTPUT_FOLDER)/metrics_test

test: $(TEST_HELLO) $(TEST_DBG) $(TEST_AUTH) $(TEST_USERS) $(TEST_REQUEST) \
      $(TEST_CONNECT) $(TEST_COPY) $(TEST_NETUTILS) $(TEST_SELECTOR_BLOCK) \
      $(TEST_METRICS)
	$(TEST_HELLO)
	$(TEST_DBG)
	$(TEST_AUTH)
	$(TEST_USERS)
	$(TEST_REQUEST)
	$(TEST_CONNECT)
	$(TEST_COPY)
	$(TEST_NETUTILS)
	$(TEST_SELECTOR_BLOCK)
	$(TEST_METRICS)

$(TEST_AUTH): test/auth_test.c src/server/auth.c src/shared/buffer.c
	mkdir -p $(OUTPUT_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) $^ -o $(TEST_AUTH)

$(TEST_USERS): test/users_test.c src/server/users.c
	mkdir -p $(OUTPUT_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) $^ -o $(TEST_USERS)

$(TEST_REQUEST): test/request_test.c src/server/request.c src/shared/buffer.c
	mkdir -p $(OUTPUT_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) $^ -o $(TEST_REQUEST)

# connect_test sólo ejercita request_connect_errno_rep (lógica pura), pero
# connect.c referencia selector_register/selector_fd_set_nio: hay que linkear
# selector.c (símbolos sin resolver) y -pthread (LD_FLAGS), que selector usa.
$(TEST_CONNECT): test/connect_test.c src/server/connect.c src/shared/selector.c
	mkdir -p $(OUTPUT_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) $(LD_FLAGS) $^ -o $(TEST_CONNECT)

# copy_test arma un selector real + socketpairs: linkea copy.c + selector.c +
# buffer.c, con -pthread (selector usa pthread). No depende de socks5nio.c.
$(TEST_COPY): test/copy_test.c src/server/copy.c src/shared/selector.c src/shared/buffer.c
	mkdir -p $(OUTPUT_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) $(LD_FLAGS) $^ -o $(TEST_COPY)

$(TEST_NETUTILS): test/netutils_test.c src/shared/netutils.c src/shared/buffer.c
	mkdir -p $(OUTPUT_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) $^ -o $(TEST_NETUTILS)

$(TEST_SELECTOR_BLOCK): test/selector_block_test.c src/shared/selector.c
	mkdir -p $(OUTPUT_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) $(LD_FLAGS) $^ -o $(TEST_SELECTOR_BLOCK)

$(TEST_METRICS): test/metrics_test.c src/server/metrics.c
	mkdir -p $(OUTPUT_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) $^ -o $(TEST_METRICS)

# integración sobre el socket real (levanta el server y habla SOCKS5)
PORT?=11080
SKIP_VALGRIND_IF_MISSING?=0
integration: server
	@for t in test/*_integration.sh; do echo "--- $$t ---"; "$$t" $(PORT) || exit 1; done

# suite completa: unitarios + integración
check: test integration

# leak / use-after-free check con TRÁFICO REAL bajo valgrind (Linux + valgrind).
# Levanta el server bajo valgrind y lo atraviesa con una batería de conexiones
# SOCKS5 (CONNECT, rutas de error, cierres). Falla si hay errores o leaks.
#   make valgrind            # puerto por defecto
#   make valgrind PORT=12345 # puerto alternativo
#   make valgrind SKIP_VALGRIND_IF_MISSING=1 # saltea si falta valgrind/python3
valgrind: server
	SKIP_VALGRIND_IF_MISSING=$(SKIP_VALGRIND_IF_MISSING) bash test/valgrind_traffic.sh $(PORT)

$(TEST_HELLO): test/hello_test.c src/server/hello.c src/shared/buffer.c
	mkdir -p $(OUTPUT_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) $^ -o $(TEST_HELLO)

$(TEST_DBG): test/dbg_test.c src/server/dbg.c
	mkdir -p $(OUTPUT_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) $^ -o $(TEST_DBG)

clean:
	rm -rf $(OUTPUT_FOLDER)
	rm -rf $(OBJECTS_FOLDER)

.PHONY: all server client test integration check valgrind clean
