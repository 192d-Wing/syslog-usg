FROM alpine:3.23
RUN apk add --no-cache syslog-ng
# Config is mounted at runtime via -v
ENTRYPOINT ["syslog-ng", "-F", "--no-caps", "-f", "/etc/syslog-ng/syslog-ng.conf"]
