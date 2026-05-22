ifndef VERBOSE
.SILENT:
endif

# main build target. compiles the teamserver and client
all: ts-build client-build

# teamserver building target
ts-build:
	@ echo "[*] building teamserver"
	@ ./teamserver/Install.sh
	@ cd teamserver; GO111MODULE="on" go build -ldflags="-s -w -X cmd.VersionCommit=$(git rev-parse HEAD)" -o ../havoc main.go
	@ if [ "$$(uname -s)" = "Linux" ]; then \
	      sudo setcap 'cap_net_bind_service=+ep' havoc 2>/dev/null || true; \
	  fi

dev-ts-compile:
	@ echo "[*] compile teamserver"
	@ cd teamserver; GO111MODULE="on" go build -ldflags="-s -w -X cmd.VersionCommit=$(git rev-parse HEAD)" -o ../havoc main.go 

ts-cleanup: 
	@ echo "[*] teamserver cleanup"
	@ rm -rf ./teamserver/bin
	@ rm -rf ./data/loot
	@ rm -rf ./data/x86_64-w64-mingw32-cross 
	@ rm -rf ./data/havoc.db
	@ rm -rf ./data/server.*
	@ rm -rf ./teamserver/.idea
	@ rm -rf ./havoc

# client building and cleanup targets
client-build:
	@ echo "[*] building client"
	@ git submodule update --init --recursive
	@ mkdir -p client/Build
	@ if [ "$$(uname -s)" = "Darwin" ]; then \
	      QT5_PREFIX=$$(brew --prefix qt@5 2>/dev/null); \
	      cd client/Build && cmake .. -DCMAKE_PREFIX_PATH="$$QT5_PREFIX"; \
	  else \
	      cd client/Build && cmake ..; \
	  fi
	@ if [ -d "client/Modules" ]; then echo "Modules installed"; else git clone https://github.com/HavocFramework/Modules client/Modules --single-branch --branch `git rev-parse --abbrev-ref HEAD`; fi
	@ cmake --build client/Build -- -j 4

client-cleanup:
	@ echo "[*] client cleanup"
	@ rm -rf ./client/Build
	@ rm -rf ./client/Bin/*
	@ rm -rf ./client/Data/database.db
	@ rm -rf ./client/.idea
	@ rm -rf ./client/cmake-build-debug
	@ rm -rf ./client/Havoc
	@ rm -rf ./client/Modules


# cleanup target 
clean: ts-cleanup client-cleanup
	@ rm -rf ./data/*.db
	@ rm -rf payloads/Demon/.idea
