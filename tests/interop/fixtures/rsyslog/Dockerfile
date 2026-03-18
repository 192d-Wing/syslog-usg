FROM alpine:3.23
RUN apk add --no-cache rsyslog
# Config is mounted at runtime via -v
ENTRYPOINT ["rsyslogd", "-n", "-f", "/etc/rsyslog.conf"]
