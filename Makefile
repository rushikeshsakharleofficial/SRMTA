# SRMTA Build Makefile
# Build, package, and install targets for RPM and DEB distributions

VERSION    ?= 1.0.0
BUILD_TIME := $(shell date -u +%Y%m%d%H%M%S)
GIT_COMMIT := $(shell git describe --tags --always 2>/dev/null || echo "dev")
LDFLAGS    := -s -w -X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME) -X main.gitCommit=$(GIT_COMMIT)
BINARY     := srmta

PREFIX     ?= /usr
SBINDIR    ?= $(PREFIX)/sbin
SYSCONFDIR ?= /etc
UNITDIR    ?= /lib/systemd/system
SPOOLDIR   ?= /var/spool/srmta
LOGDIR     ?= /var/log/srmta
DATADIR    ?= $(PREFIX)/share/srmta

.PHONY: all build clean install uninstall rpm deb test

# ── Build ────────────────────────────────────────────────────────────────
all: build

build:
	CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o $(BINARY) ./cmd/srmta

build-all: build
	@echo "Build complete: ./$(BINARY)"

# ── Test ─────────────────────────────────────────────────────────────────
test:
	go test -v -race ./...

bench:
	go test -bench=. -benchmem ./...

lint:
	golangci-lint run ./...

# ── Install (bare metal) ────────────────────────────────────────────────
install: build
	@echo "Installing SRMTA..."
	install -D -m 0755 $(BINARY) $(DESTDIR)$(SBINDIR)/$(BINARY)

	# Systemd
	install -D -m 0644 deploy/systemd/srmta.service $(DESTDIR)$(UNITDIR)/srmta.service
	install -D -m 0644 deploy/systemd/srmta.socket  $(DESTDIR)$(UNITDIR)/srmta.socket

	# Configuration
	install -d -m 0750 $(DESTDIR)$(SYSCONFDIR)/srmta
	install -d -m 0750 $(DESTDIR)$(SYSCONFDIR)/srmta/config.d
	install -d -m 0750 $(DESTDIR)$(SYSCONFDIR)/srmta/dkim
	install -m 0640 configs/config.example.yaml $(DESTDIR)$(SYSCONFDIR)/srmta/config.yaml
	install -m 0600 deploy/systemd/srmta.env    $(DESTDIR)$(SYSCONFDIR)/srmta/srmta.env
	for f in configs/config.d/*.yaml; do \
		install -m 0640 "$$f" $(DESTDIR)$(SYSCONFDIR)/srmta/config.d/; \
	done

	# Data directories
	install -d -m 0750 $(DESTDIR)$(SPOOLDIR)
	install -d -m 0750 $(DESTDIR)$(LOGDIR)

	# Migrations
	install -d -m 0755 $(DESTDIR)$(DATADIR)/migrations
	install -m 0644 migrations/*.sql $(DESTDIR)$(DATADIR)/migrations/

	@echo "SRMTA installed. Run: systemctl enable --now srmta.service"

uninstall:
	rm -f  $(DESTDIR)$(SBINDIR)/$(BINARY)
	rm -f  $(DESTDIR)$(UNITDIR)/srmta.service
	rm -f  $(DESTDIR)$(UNITDIR)/srmta.socket
	rm -rf $(DESTDIR)$(DATADIR)
	@echo "SRMTA uninstalled. Config and data directories preserved."
	@echo "  Remove manually: $(SYSCONFDIR)/srmta $(SPOOLDIR) $(LOGDIR)"

# ── RPM ──────────────────────────────────────────────────────────────────
rpm: build
	@echo "Building RPM..."
	mkdir -p rpmbuild/{SPECS,SOURCES,BUILD,RPMS,SRPMS}
	tar czf rpmbuild/SOURCES/srmta-$(VERSION).tar.gz \
		--transform="s,^,srmta-$(VERSION)/," \
		--exclude=rpmbuild --exclude=.git \
		.
	rpmbuild -bb deploy/rpm/srmta.spec \
		--define "_topdir $(PWD)/rpmbuild" \
		--define "_version $(VERSION)"
	@echo "RPM built: rpmbuild/RPMS/"

# ── DEB ──────────────────────────────────────────────────────────────────
deb: build
	@echo "Building DEB..."
	mkdir -p debbuild/srmta-$(VERSION)
	cp -r . debbuild/srmta-$(VERSION)/
	cp -r deploy/deb/debian debbuild/srmta-$(VERSION)/debian
	cd debbuild/srmta-$(VERSION) && dpkg-buildpackage -us -uc -b
	@echo "DEB built: debbuild/"

# ── Clean ────────────────────────────────────────────────────────────────
clean:
	rm -f $(BINARY)
	rm -rf rpmbuild debbuild
	go clean
