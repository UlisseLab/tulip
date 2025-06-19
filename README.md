# 🌷 Tulip

Tulip is a flow analyzer meant for use during Attack / Defence CTF competitions.

It allows players to easily find some traffic related to their service and automatically generates python snippets to replicate attacks.

## Origins

Tulip was developed by Team Europe for use in the first International Cyber Security Challenge. This is the official fork of the Ulisse CTF Team.

Originally, Tulip was based on the [flower](https://github.com/secgroup/flower), but it contains quite some changes:

- New front-end (typescript / react / tailwind)
- New ingestor code, based on gopacket
- IPv6 support
- Vastly improved filter and tagging system.
- Deep links for easy collaboration
- Added an http decoding pass for compressed data
- Synchronized with Suricata.
- Flow diffing
- Time and size-based plots for correlation.
- Linking HTTP sessions together based on cookies (Experimental, disabled by default)

## Screenshots

![](./demo_images/demo1.png)
![](./demo_images/demo2.png)
![](./demo_images/demo3.png)

## Configuration

All configuration is done through the `.env` file.

You can find example values and descriptions in the `.env.example` file.

## Usage

The stack can be started with docker-compose, after creating an `.env` file. See `.env.example` as an example of how to configure your environment.

```shell
cp .env.example .env
# Now edit the .env file with your favourite text editor...
docker compose up -d --build
```

### Ingesting traffic

#### TLDR

```
sudo tcpdump -n --immediate-mode -s 65535 -U -w - | nc localhost 9999
# or
dumpcap -i eth0 -w - -F pcap  | nc localhost 9999
```


#### Long explanation

The `ingestor` service is responsible for reading traffic from a pcap file or live interface and writing it to the shared volume.

You can configure the

- listen interface
- rotation interval
  in the `.env` file.

The higher the rotation interval, the more delay there will be before the traffic is visible in Tulip. The default is 30 sec, which should be sufficient for most CTFs.

> [!WARNING] The assembler only maintains flow for a single PCAP file, so setting the rotation interval too low could result in the assembler not being able to link packets together in a flow.

## Suricata synchronization

### Metadata

Tags are read from the metadata field of a rule. For example, here's a simple rule to detect a path traversal:

```
alert tcp any any -> any any (msg: "Path Traversal-../"; flow:to_server; content: "../"; metadata: tag path_traversal; sid:1; rev: 1;)
```

Once this rule is seen in traffic, the `path_traversal` tag will automatically be added to the filters in Tulip.

### eve.json

Suricata alerts are read directly from the `eve.json` file. Because this file can get quite verbose when all extensions are enabled, it is recommended to strip the config down a fair bit. For example:

```yaml
# ...
- eve-log:
    enabled: yes
    filetype: regular #regular|syslog|unix_dgram|unix_stream|redis
    filename: eve.json
    pcap-file: false
    community-id: false
    community-id-seed: 0
    types:
      - alert:
          metadata: yes
          # Enable the logging of tagged packets for rules using the
          # "tag" keyword.
          tagged-packets: yes
# ...
```

Sessions with matched alerts will be highlighted in the front-end and include which rule was matched.

# Security

Your Tulip instance will probably contain sensitive CTF information, like flags stolen from your machines. If you expose it to the internet and other people find it, you risk losing additional flags. It is recommended to host it on an internal network (for instance behind a VPN) or to put Tulip behind some form of authentication.

# Contributing

If you have an idea for a new feature, bug fixes, UX improvements, or other contributions, feel free to open a pull request or create an issue!
When opening a pull request, please target the `devel` branch.

# Credits

Tulip was written by [@RickdeJager](https://github.com/rickdejager) and [@Bazumo](https://github.com/bazumo), with additional help from [@Sijisu](https://github.com/sijisu). Thanks to our fellow Team Europe players and coaches for testing, feedback and suggestions. Finally, thanks to the team behind [flower](https://github.com/secgroup/flower) for opensourcing their tooling.
