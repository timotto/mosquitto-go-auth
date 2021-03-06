CFLAGS := -I/usr/local/include -fPIC
LDFLAGS := -shared

UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Darwin)
	LDFLAGS += -undefined dynamic_lookup
else ifeq ($(UNAME_S),Linux)
	LDFLAGS += -Wl,-unresolved-symbols=ignore-all
endif

all:
	@echo "Bulding for $(UNAME_S)"
	env CGO_CFLAGS="$(CFLAGS)" go build -buildmode=c-archive go-auth.go
	env CGO_LDFLAGS="$(LDFLAGS)" go build -buildmode=c-shared -o go-auth.so
	go build pw-gen/pw.go

test:
	go test ./backends ./cache ./hashing -v -count=1

test-backends:
	go test ./backends -v -failfast -count=1

test-cache:
	go test ./cache -v -failfast -count=1

test-hashing:
	go test ./hashing -v -failfast -count=1

service:
	@echo "Generating gRPC code from .proto files"
	@go generate grpc/grpc.go

clean:
	rm -f go-auth.h
	rm -f go-auth.so
	rm -f pw