socat tcp:${PCAP_OVER_IP} - | suricata -c /etc/suricata/suricata.yaml -r /dev/stdin
