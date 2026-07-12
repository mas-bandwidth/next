# Network Next Makefile

RELAY_VERSION := "relay-userspace-debug"

CXX_FLAGS := -g -Wall -Wextra

OS := $(shell uname -s | tr A-Z a-z)
SDK_LDFLAGS = -lsodium -lpthread -lm -lcurl
ifeq ($(OS),darwin)
APP_LDFLAGS = -framework CoreFoundation -framework SystemConfiguration
else
APP_LDFLAGS = 
endif
CXX = g++

SDKNAME5 = libnext

MODULE ?= "github.com/networknext/next/modules/common"

BUILD_TIME ?= $(shell date -u +'%Y-%m-%d|%H:%M:%S')
COMMIT_MESSAGE ?= $(shell git log -1 --pretty=%B | tr "\n" " " | tr \' '*')
COMMIT_HASH ?= $(shell git rev-parse --short HEAD) 

# Build and run tests by default

.PHONY: test
test: build
	./run test

# Update schemas in module directories (golang can only include them in module source if they are under the module directory)

.PHONY: update-schemas
update-schemas:
	@cp -f schemas/pubsub/client_relay_ping.json cmd/server_backend
	@cp -f schemas/pubsub/server_relay_ping.json cmd/server_backend
	@cp -f schemas/pubsub/server_init.json cmd/server_backend
	@cp -f schemas/pubsub/server_update.json cmd/server_backend
	@cp -f schemas/pubsub/session_update.json cmd/server_backend
	@cp -f schemas/pubsub/session_summary.json cmd/server_backend
	@cp -f schemas/pubsub/relay_update.json cmd/relay_backend
	@cp -f schemas/pubsub/relay_to_relay_ping.json cmd/relay_backend
	@cp -f schemas/pubsub/route_matrix_update.json cmd/relay_backend

# Clean, build and rebuild

.PHONY: build
build: update-schemas
	@make -s build-fast

.PHONY: build-fast
build-fast: dist/$(SDKNAME5).so dist/relay-userspace-debug dist/client dist/server dist/test dist/raspberry_server dist/raspberry_client dist/func_server dist/func_client $(shell ./scripts/all_commands.sh)

.PHONY: rebuild
rebuild: clean update-schemas ## rebuild everything
	@echo rebuilding...
	@make build

.PHONY: clean
clean: ## clean everything
	@rm -rf dist
	@rm -rf logs
	@mkdir -p dist

# Build most golang services

dist/%: cmd/%/*.go $(shell find modules -name '*.go')
	@go build -ldflags "-s -w -X $(MODULE).buildTime=$(BUILD_TIME) -X \"$(MODULE).commitMessage=$(COMMIT_MESSAGE)\" -X $(MODULE).commitHash=$(COMMIT_HASH) -X $(MODULE).tag=$(SEMAPHORE_GIT_TAG_NAME)" -o $@ $(<D)/*.go
	@echo $@

# Build artifacts

dist/%.tar.gz: dist/%
	@go run tools/build_artifact/build_artifact.go $@
	@echo $@

# Format code

.PHONY: format
format:
	@gofmt -s -w .
	@./scripts/tabs2spaces.sh

# Build sdk

SDK_FLAGS := -DNEXT_DEVELOPMENT=1 -DNEXT_COMPILE_WITH_TESTS=1 

dist/$(SDKNAME5).so: $(shell find sdk -type f)
	@cd dist && $(CXX) $(CXX_FLAGS) $(SDK_FLAGS) -fPIC -I../sdk/include -I../sdk/serialize -shared -o $(SDKNAME5).so ../sdk/source/*.cpp $(SDK_LDFLAGS) $(APP_LDFLAGS)
	@echo $@

dist/client: dist/$(SDKNAME5).so cmd/client/client.cpp
	@cd dist && $(CXX) $(CXX_FLAGS) $(SDK_FLAGS) -I../sdk/include -I../sdk/serialize -o client ../cmd/client/client.cpp $(SDKNAME5).so $(APP_LDFLAGS)
	@echo $@

dist/server: dist/$(SDKNAME5).so cmd/server/server.cpp
	@cd dist && $(CXX) $(CXX_FLAGS) $(SDK_FLAGS) -I../sdk/include -I../sdk/serialize -o server ../cmd/server/server.cpp $(SDKNAME5).so $(APP_LDFLAGS)
	@echo $@

dist/test: dist/$(SDKNAME5).so sdk/test.cpp
	@cd dist && $(CXX) $(CXX_FLAGS) $(SDK_FLAGS) -I../sdk/include -I../sdk/serialize -o test ../sdk/test.cpp $(SDKNAME5).so $(APP_LDFLAGS)
	@echo $@

# Build the userspace-mode XDP relay (one datapath source, non-BPF backend -- see
# relay/CONSOLIDATION.md). this is the relay the functional tests and local dev run.

USERSPACE_RELAY_SOURCES = relay/xdp/relay.c relay/xdp/relay_platform.c relay/xdp/relay_base64.c relay/xdp/relay_ping_history.c relay/xdp/relay_manager.c relay/xdp/relay_main.c relay/xdp/relay_ping.c relay/xdp/relay_config.c relay/xdp/relay_userspace.c relay/xdp/relay_xdp.c

dist/relay-userspace-debug: relay/xdp/*.c relay/xdp/*.h
	@cc -g -DRELAY_USERSPACE -DRELAY_TEST=1 -DRELAY_LOGS=1 -DRELAY_VERSION=\"$(RELAY_VERSION)\" -O2 -o dist/relay-userspace-debug $(USERSPACE_RELAY_SOURCES) $(SDK_LDFLAGS) $(APP_LDFLAGS)
	@echo $@

# Build the userspace relay with address sanitizer, for running the relay functional tests against it

dist/relay-userspace-debug-asan: relay/xdp/*.c relay/xdp/*.h
	@cc -g -fsanitize=address -fno-omit-frame-pointer -DRELAY_USERSPACE -DRELAY_TEST=1 -DRELAY_LOGS=1 -DRELAY_VERSION=\"$(RELAY_VERSION)\" -O2 -o dist/relay-userspace-debug-asan $(USERSPACE_RELAY_SOURCES) $(SDK_LDFLAGS) $(APP_LDFLAGS)
	@echo $@

# Functional tests (sdk)

dist/func_server: dist/$(SDKNAME5).so cmd/func_server/*
	@cd dist && $(CXX) $(CXX_FLAGS) -I../sdk/include -I../sdk/serialize -o func_server ../cmd/func_server/func_server.cpp $(SDKNAME5).so $(APP_LDFLAGS)
	@echo $@

dist/func_client: dist/$(SDKNAME5).so cmd/func_client/*
	@cd dist && $(CXX) $(CXX_FLAGS) -I../sdk/include -I../sdk/serialize -o func_client ../cmd/func_client/func_client.cpp $(SDKNAME5).so $(APP_LDFLAGS)
	@echo $@

# Raspberry

dist/raspberry_client: dist/$(SDKNAME5).so cmd/raspberry_client/raspberry_client.cpp
	@cd dist && $(CXX) $(CXX_FLAGS) -I../sdk/include -I../sdk/serialize -o raspberry_client ../cmd/raspberry_client/raspberry_client.cpp $(SDKNAME5).so $(APP_LDFLAGS)
	@echo $@

dist/raspberry_server: dist/$(SDKNAME5).so cmd/raspberry_server/raspberry_server.cpp
	@cd dist && $(CXX) $(CXX_FLAGS) -I../sdk/include -I../sdk/serialize -o raspberry_server ../cmd/raspberry_server/raspberry_server.cpp $(SDKNAME5).so $(APP_LDFLAGS)
	@echo $@
