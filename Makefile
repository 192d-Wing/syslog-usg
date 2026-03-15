# syslog-usg — Build and release targets
#
# Usage:
#   make build          # Debug build
#   make release        # Optimized release build
#   make test           # Run all tests
#   make check          # Clippy + fmt + audit + deny
#   make docker         # Build Docker image
#   make install        # Install binary + config + systemd unit
#   make clean          # Remove build artifacts

BINARY     := syslog-usg
VERSION    := $(shell grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')
TARGET_DIR := target
RELEASE    := $(TARGET_DIR)/release/$(BINARY)
INSTALL_DIR := /usr/local/bin
CONFIG_DIR := /etc/syslog-usg
STATE_DIR  := /var/lib/syslog-usg
LOG_DIR    := /var/log/syslog-usg

.PHONY: build release test check fmt clippy audit deny fuzz bench \
        docker docker-compose install uninstall clean help

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

build: ## Debug build
	cargo build

release: ## Optimized release build
	cargo build --release
	@echo "Binary: $(RELEASE)"
	@ls -lh $(RELEASE)

# ---------------------------------------------------------------------------
# Testing & quality
# ---------------------------------------------------------------------------

test: ## Run all tests
	cargo test --workspace

check: fmt clippy audit deny ## Run all quality checks

fmt: ## Check formatting
	cargo fmt --all -- --check

clippy: ## Run clippy with strict warnings
	cargo clippy --all-targets --all-features -- -D warnings

audit: ## Check for known vulnerabilities
	cargo audit

deny: ## Check licenses, bans, sources
	cargo deny check

fuzz: ## Run all fuzz targets (30 seconds each)
	@cd fuzz && for target in $$(cargo fuzz list 2>/dev/null); do \
		echo "--- Fuzzing $$target ---"; \
		cargo fuzz run $$target -- -max_total_time=30 || true; \
	done

bench: ## Run benchmarks
	cargo bench -p syslog-bench

# ---------------------------------------------------------------------------
# Docker
# ---------------------------------------------------------------------------

docker: ## Build Docker image
	docker build -f container/Dockerfile -t $(BINARY):$(VERSION) -t $(BINARY):latest .

docker-compose: ## Start with docker-compose
	docker compose -f container/docker-compose.yml up -d

docker-down: ## Stop docker-compose
	docker compose -f container/docker-compose.yml down

# ---------------------------------------------------------------------------
# Install (Linux)
# ---------------------------------------------------------------------------

install: release ## Install binary, config, and systemd unit
	@echo "Installing $(BINARY) v$(VERSION)..."
	# Binary
	install -Dm755 $(RELEASE) $(INSTALL_DIR)/$(BINARY)
	# Config directory
	install -dm750 -o root -g syslog $(CONFIG_DIR)
	install -dm700 -o syslog -g syslog $(STATE_DIR)
	install -dm750 -o syslog -g syslog $(LOG_DIR)
	# Install default config if not present
	@if [ ! -f $(CONFIG_DIR)/config.toml ]; then \
		install -Dm640 -o root -g syslog examples/config-minimal.toml $(CONFIG_DIR)/config.toml; \
		echo "Installed default config to $(CONFIG_DIR)/config.toml"; \
	else \
		echo "Config already exists at $(CONFIG_DIR)/config.toml — not overwriting"; \
	fi
	# Systemd unit
	install -Dm644 dist/syslog-usg.service /etc/systemd/system/$(BINARY).service
	systemctl daemon-reload
	@echo ""
	@echo "Installation complete. Next steps:"
	@echo "  1. Edit $(CONFIG_DIR)/config.toml"
	@echo "  2. sudo systemctl enable --now $(BINARY)"

uninstall: ## Remove installed files
	systemctl stop $(BINARY) 2>/dev/null || true
	systemctl disable $(BINARY) 2>/dev/null || true
	rm -f /etc/systemd/system/$(BINARY).service
	rm -f $(INSTALL_DIR)/$(BINARY)
	systemctl daemon-reload
	@echo "Binary and service removed. Config and state preserved at:"
	@echo "  $(CONFIG_DIR)/"
	@echo "  $(STATE_DIR)/"

# ---------------------------------------------------------------------------
# Misc
# ---------------------------------------------------------------------------

clean: ## Remove build artifacts
	cargo clean
	rm -rf fuzz/target

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'
