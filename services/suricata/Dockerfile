FROM jasonish/suricata
RUN dnf install -y socat

COPY run.sh /run.sh
RUN chmod +x /run.sh

WORKDIR /suricata

CMD ["/run.sh"]

