include ./Makefile.inc

SERVER_SOURCES=$(wildcard src/server/*.c)
CLIENT_SOURCES=$(wildcard src/client/*.c)
SHARED_SOURCES=$(wildcard src/shared/*.c)

SERVER_OBJECTS=$(SERVER_SOURCES:src/%.c=obj/%.o)
CLIENT_OBJECTS=$(CLIENT_SOURCES:src/%.c=obj/%.o)
SHARED_OBJECTS=$(SHARED_SOURCES:src/%.c=obj/%.o)

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
	$(COMPILER) $(COMPILER_FLAGS) -c $< -o $@

# tests unitarios (harness plano en C, sin libcheck)
TEST_HELLO=$(OUTPUT_FOLDER)/hello_test
TEST_DBG=$(OUTPUT_FOLDER)/dbg_test
TEST_AUTH=$(OUTPUT_FOLDER)/auth_test
TEST_USERS=$(OUTPUT_FOLDER)/users_test
TEST_REQUEST=$(OUTPUT_FOLDER)/request_test

test: $(TEST_HELLO) $(TEST_DBG) $(TEST_AUTH) $(TEST_USERS) $(TEST_REQUEST)
	$(TEST_HELLO)
	$(TEST_DBG)
	$(TEST_AUTH)
	$(TEST_USERS)
	$(TEST_REQUEST)

$(TEST_AUTH): test/auth_test.c src/server/auth.c src/shared/buffer.c
	mkdir -p $(OUTPUT_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) $^ -o $(TEST_AUTH)

$(TEST_USERS): test/users_test.c src/server/users.c
	mkdir -p $(OUTPUT_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) $^ -o $(TEST_USERS)

$(TEST_REQUEST): test/request_test.c src/server/request.c src/shared/buffer.c
	mkdir -p $(OUTPUT_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) $^ -o $(TEST_REQUEST)

# integración sobre el socket real (levanta el server y habla SOCKS5)
PORT?=11080
integration: server
	@for t in test/*_integration.sh; do echo "--- $$t ---"; "$$t" $(PORT) || exit 1; done

# suite completa: unitarios + integración
check: test integration

$(TEST_HELLO): test/hello_test.c src/server/hello.c src/shared/buffer.c
	mkdir -p $(OUTPUT_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) $^ -o $(TEST_HELLO)

$(TEST_DBG): test/dbg_test.c src/server/dbg.c
	mkdir -p $(OUTPUT_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) $^ -o $(TEST_DBG)

clean:
	rm -rf $(OUTPUT_FOLDER)
	rm -rf $(OBJECTS_FOLDER)

.PHONY: all server client test integration check clean
