FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y rsyslog && rm -rf /var/lib/apt/lists/*
COPY rsyslog.conf /etc/rsyslog.conf
COPY 50-netguard.conf /etc/rsyslog.d/50-netguard.conf
RUN mkdir -p /var/log/netguard
EXPOSE 514/udp
CMD ["rsyslogd","-n"]
