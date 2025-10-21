.PHONY: help build test run clean fmt lint install-deps

help:
	@echo "Catbird MLS - Development Commands"
	@echo ""
	@echo "make build          - Build all components"
	@echo "make test           - Run all tests"
	@echo "make run            - Run backend server"
	@echo "make clean          - Clean build artifacts"
	@echo "make fmt            - Format code"
	@echo "make lint           - Run linters"
	@echo "make install-deps   - Install dependencies"

build:
	@echo "Building server..."
	cd server && cargo build
	@echo "Building MLS FFI..."
	cd mls-ffi && cargo build

build-release:
	@echo "Building release..."
	cd server && cargo build --release
	cd mls-ffi && cargo build --release

test:
	@echo "Running server tests..."
	cd server && cargo test
	@echo "Running FFI tests..."
	cd mls-ffi && cargo test

run:
	@echo "Starting server..."
	cd server && DATABASE_URL=sqlite:catbird.db cargo run

run-postgres:
	@echo "Starting server with PostgreSQL..."
	cd server && DATABASE_URL=postgres://localhost/catbird cargo run

clean:
	@echo "Cleaning..."
	cd server && cargo clean
	cd mls-ffi && cargo clean
	rm -f catbird.db catbird.db-shm catbird.db-wal

fmt:
	@echo "Formatting code..."
	cd server && cargo fmt
	cd mls-ffi && cargo fmt

lint:
	@echo "Running clippy..."
	cd server && cargo clippy -- -D warnings
	cd mls-ffi && cargo clippy -- -D warnings

install-deps:
	@echo "Installing Rust toolchain..."
	rustup update stable
	@echo "Installing cargo tools..."
	cargo install sqlx-cli
	cargo install cargo-watch

watch:
	@echo "Watching for changes..."
	cd server && cargo watch -x run

db-setup:
	@echo "Setting up database..."
	createdb catbird || true
	cd server && DATABASE_URL=postgres://localhost/catbird cargo run

# iOS targets
build-ios-sim:
	@echo "Building FFI for iOS simulator..."
	cd mls-ffi && cargo build --release --target x86_64-apple-ios

build-ios-device:
	@echo "Building FFI for iOS device..."
	cd mls-ffi && cargo build --release --target aarch64-apple-ios
	
docker-build:
	@echo "Building Docker image..."
	docker build -t catbird-server -f server/Dockerfile .

docker-run:
	@echo "Running Docker container..."
	docker run -p 3000:3000 -e DATABASE_URL=sqlite::memory: catbird-server

all: build test
