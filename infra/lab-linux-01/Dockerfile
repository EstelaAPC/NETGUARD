FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        iptables \
        iproute2 \
        iputils-ping \
        procps \
        rsyslog \
        snmp \
        snmpd \
        util-linux \
    && rm -rf /var/lib/apt/lists/*

COPY snmpd.conf /etc/snmp/snmpd.conf
COPY rsyslog-forward.conf /etc/rsyslog.d/99-netguard-forward.conf
COPY netguard-lab-lib.sh /usr/local/lib/netguard-lab-lib.sh
COPY netguard-lab-control.sh /usr/local/bin/netguard-lab-control
COPY start.sh /usr/local/bin/start-lab-linux-01
COPY netguard-preloop-demo.sh /usr/local/bin/netguard-preloop-demo

RUN chmod +x \
        /usr/local/bin/netguard-lab-control \
        /usr/local/bin/start-lab-linux-01 \
        /usr/local/bin/netguard-preloop-demo

EXPOSE 161/udp

CMD ["/usr/local/bin/start-lab-linux-01"]
