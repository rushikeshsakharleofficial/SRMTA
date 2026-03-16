%global debug_package %{nil}

%define _version    1.1.0
%define _release    1%{?dist}
%define _name       srmta

Name:       %{_name}
Version:    %{_version}
Release:    %{_release}
Summary:    SRMTA — Scalable RFC-Compliant Mail Transfer Agent
License:    MIT
URL:        https://github.com/rushikeshsakharleofficial/SRMTA
Source0:    %{name}-%{version}.tar.gz

BuildRequires:  golang >= 1.22
BuildRequires:  systemd-rpm-macros
BuildRequires:  make

# ── Hard dependencies ────────────────────────────────────────────────
Requires:       systemd
Requires:       ca-certificates
Requires:       openssl >= 1.1
Requires:       glibc
Requires:       bind-utils
Requires:       logrotate
Requires(pre):  shadow-utils

# ── Recommended (installed by default if available) ──────────────────
Recommends:     postgresql-server >= 14
Recommends:     redis >= 6
Recommends:     nodejs >= 20
Recommends:     firewalld

# ── Suggested (optional enhancements) ────────────────────────────────
Suggests:       grafana
Suggests:       prometheus2
Suggests:       certbot
Suggests:       opendkim

# ── Conflicts with other MTAs ────────────────────────────────────────
Conflicts:      postfix
Conflicts:      sendmail
Conflicts:      exim

%description
SRMTA is a production-grade, horizontally scalable, RFC 5321/5322 compliant
Mail Transfer Agent built in Go. Features include ESMTP with STARTTLS, DKIM
signing, multi-spool queue architecture, IP pool health management, bounce
classification, auto-suppression, and Prometheus metrics.

%prep
%setup -q

%build
CGO_ENABLED=0 go build \
    -ldflags="-s -w -X main.version=%{version} -X main.buildTime=$(date -u +%%Y%%m%%d%%H%%M%%S)" \
    -o %{_name} ./cmd/srmta

%install
# Binary
install -D -m 0755 %{_name} %{buildroot}%{_sbindir}/%{_name}

# Systemd units
install -D -m 0644 deploy/systemd/srmta.service %{buildroot}/lib/systemd/system/%{_name}.service
install -D -m 0644 deploy/systemd/srmta.socket  %{buildroot}/lib/systemd/system/%{_name}.socket

# Configuration
install -D -m 0640 configs/config.example.yaml %{buildroot}%{_sysconfdir}/%{_name}/config.yaml
install -d -m 0750 %{buildroot}%{_sysconfdir}/%{_name}/config.d
install -d -m 0750 %{buildroot}%{_sysconfdir}/%{_name}/dkim

# Install example sub-configs
for f in configs/config.d/*.yaml; do
    install -m 0640 "$f" %{buildroot}%{_sysconfdir}/%{_name}/config.d/
done

# Environment file (secrets)
install -D -m 0600 deploy/systemd/srmta.env %{buildroot}%{_sysconfdir}/%{_name}/srmta.env

# Spool and log directories
install -d -m 0750 %{buildroot}%{_localstatedir}/spool/%{_name}
install -d -m 0750 %{buildroot}%{_localstatedir}/log/%{_name}

# Database migrations
install -d -m 0755 %{buildroot}%{_datadir}/%{_name}/migrations
install -m 0644 migrations/*.sql %{buildroot}%{_datadir}/%{_name}/migrations/

# Man page placeholder
install -d -m 0755 %{buildroot}%{_mandir}/man8

%pre
# Create srmta user and group if they don't exist
getent group %{_name} >/dev/null || groupadd -r %{_name}
getent passwd %{_name} >/dev/null || \
    useradd -r -g %{_name} -d %{_localstatedir}/spool/%{_name} \
    -s /sbin/nologin -c "SRMTA Mail Transfer Agent" %{_name}
exit 0

%post
%systemd_post %{_name}.service %{_name}.socket
# Set ownership
chown -R %{_name}:%{_name} %{_localstatedir}/spool/%{_name}
chown -R %{_name}:%{_name} %{_localstatedir}/log/%{_name}
chown -R root:%{_name} %{_sysconfdir}/%{_name}

echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  SRMTA v1.1.0 installed successfully                        ║"
echo "║                                                              ║"
echo "║  IMPORTANT: Set required secrets before starting:            ║"
echo "║    sudo vim /etc/srmta/srmta.env                             ║"
echo "║    -> JWT_SECRET, WEBHOOK_SECRET, DB_PASSWORD, REDIS_PASSWORD║"
echo "║    -> Generate with: openssl rand -hex 32                    ║"
echo "║                                                              ║"
echo "║  Config:  /etc/srmta/config.yaml                             ║"
echo "║  Sub-cfg: /etc/srmta/config.d/*.yaml                        ║"
echo "║  Secrets: /etc/srmta/srmta.env                               ║"
echo "║  Spool:   /var/spool/srmta/                                  ║"
echo "║  Logs:    /var/log/srmta/                                    ║"
echo "║                                                              ║"
echo "║  Enable and start:                                           ║"
echo "║    systemctl enable --now srmta.socket                       ║"
echo "║    systemctl enable --now srmta.service                      ║"
echo "║                                                              ║"
echo "║  Apply database schema:                                      ║"
echo "║    psql -U srmta -f /usr/share/srmta/migrations/init_postgres.sql ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

%preun
%systemd_preun %{_name}.service %{_name}.socket

%postun
%systemd_postun_with_restart %{_name}.service

%files
%license LICENSE
%doc README.md
%{_sbindir}/%{_name}
/lib/systemd/system/%{_name}.service
/lib/systemd/system/%{_name}.socket
%dir %attr(0750,root,%{_name}) %{_sysconfdir}/%{_name}
%config(noreplace) %attr(0640,root,%{_name}) %{_sysconfdir}/%{_name}/config.yaml
%config(noreplace) %attr(0600,root,%{_name}) %{_sysconfdir}/%{_name}/srmta.env
%dir %attr(0750,root,%{_name}) %{_sysconfdir}/%{_name}/config.d
%config(noreplace) %attr(0640,root,%{_name}) %{_sysconfdir}/%{_name}/config.d/*.yaml
%dir %attr(0750,root,%{_name}) %{_sysconfdir}/%{_name}/dkim
%dir %attr(0750,%{_name},%{_name}) %{_localstatedir}/spool/%{_name}
%dir %attr(0750,%{_name},%{_name}) %{_localstatedir}/log/%{_name}
%{_datadir}/%{_name}/migrations/

%changelog
* Mon Mar 16 2026 SRMTA Team <team@linuxhardened.com> - 1.1.0-1
- Security: remove hardcoded admin/admin credentials, require DB-backed bcrypt auth
- Security: remove default JWT secret fallback, app refuses to start without JWT_SECRET
- Security: remove hardcoded DB passwords from source and configs
- Security: default SMTP auth validator now rejects all credentials
- Security: CORS restricted to explicit origin allowlist (was wildcard)
- Security: WebSocket endpoint requires JWT authentication
- Security: webhook uses separate WEBHOOK_SECRET with constant-time HMAC comparison
- Security: STARTTLS handshake failure aborts connection (no plaintext fallback)
- Security: database SSL mode defaults to "require" instead of "prefer"
- Security: message IDs use crypto.randomUUID() / crypto/rand
- Security: JWT expiry reduced from 24h to 30m
- Security: bulk send capped at 1000 messages per batch
- Security: URL-encode unsubscribe link parameters
- Security: add 1MB request body limit on webhook handler
- Fix: dashboard uses relative URLs and wss:// for WebSocket
- Fix: CSV export uses fetch with auth header instead of window.open
- Fix: log export limit capped at 50000, pagination bounds-checked
- Fix: health endpoint no longer leaks process uptime

* Sun Feb 22 2026 SRMTA Team <team@linuxhardened.com> - 1.0.0-1
- Initial release
- Go SMTP engine with ESMTP, STARTTLS, AUTH, pipelining
- Multi-spool queue with crash recovery journal
- DKIM signing, bounce classification, auto-suppression
- IP pool health scoring with warm-up controls
- Prometheus metrics exporter
- config.d/ sub-config support
