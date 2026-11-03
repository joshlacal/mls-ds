.PHONY: help build test run clean fmt lint check-codegen-guardrails install-deps

help:
	@echo "Catbird MLS - Development Commands"
	@echo ""
	@echo "make build          - Build all components"
	@echo "make build-release  - Build release binaries"
	@echo "make test           - Run all tests"
	@echo "make run            - Run backend server"
	@echo "make deploy         - Deploy to production"
	@echo "make clean          - Clean build artifacts"
	@echo "make fmt            - Format code"
	@echo "make lint           - Run linters"
	@echo "make check-codegen-guardrails - Enforce generated lexicon runtime guardrails"
	@echo "make install-deps   - Install dependencies"

build:
	@echo "Building server..."
	cd server && cargo build

build-release:
	@echo "Building release..."
	cd server && cargo build --release

test:
	@echo "Running server tests..."
	cd server && cargo test

run:
	@echo "Starting server..."
	./start_server.sh

deploy:
	@echo "Deploying to production..."
	./deploy.sh

clean:
	@echo "Cleaning..."
	cd server && cargo clean

fmt:
	@echo "Formatting code..."
	cd server && cargo fmt

lint:
	@echo "Running clippy..."
	cd server && cargo clippy -- -D warnings

check-codegen-guardrails:
	@./server/scripts/check_codegen_guardrails.sh

install-deps:
	@echo "Installing Rust toolchain..."
	rustup update stable
	@echo "Installing cargo tools..."
	cargo install sqlx-cli
	cargo install cargo-watch

watch:
	@echo "Watching for changes..."
	cd server && cargo watch -x run

# Service management
start:
	sudo systemctl start catbird-mls-server

stop:
	sudo systemctl stop catbird-mls-server

restart:
	sudo systemctl restart catbird-mls-server

status:
	sudo systemctl status catbird-mls-server --no-pager

logs:
	sudo journalctl -u catbird-mls-server -f

all: build test
