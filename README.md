<!--
SPDX-FileCopyrightText: 2018 - 2019 Nicolò Mazzucato <nicomazz@users.noreply.github.com>
SPDX-FileCopyrightText: 2018 Marco Squarcina <lavish@users.noreply.github.com>
SPDX-FileCopyrightText: 2018 nicomazz <nicolmazzucato@me.com>
SPDX-FileCopyrightText: 2018 nicomazz_dell <nicolmazzucato@me.com>
SPDX-FileCopyrightText: 2018 wert310 <310wert@gmail.com>
SPDX-FileCopyrightText: 2019 Emiliano Ciavatta <emiliano.ciavatta@studio.unibo.it>
SPDX-FileCopyrightText: 2020 nicomazz <nicomazz97@gmail.com>
SPDX-FileCopyrightText: 2022 Rick de Jager <rickdejager99@gmail.com>
SPDX-FileCopyrightText: 2022 Sijisu <mail@sijisu.eu>
SPDX-FileCopyrightText: 2024 - 2025 Eyad Issa <eyadlorenzo@gmail.com>

SPDX-License-Identifier: GPL-3.0-only
-->

# 🌷 Tulip

Tulip is a flow analyzer meant for use during Attack / Defence CTF competitions.

It allows players to easily find some traffic related to their service and automatically generates python snippets to replicate attacks.

## Screenshots

![](./demo_images/demo1.png)
![](./demo_images/demo2.png)
![](./demo_images/demo3.png)

## Model Context Protocol (NEW!)

Tulip natively supports the Model Context Protocol HTTP Streaming mode.

If your client does not support it, you can use the `mcp-proxy` service to convert the Model Context Protocol to a regular HTTP stream.

```sh
uv tool install mcp-proxy
```

and then configure your MCP client:

```json
{
  "mcpServers": {
    "mcp-proxy": {
      "command": "mcp-proxy",
      "args": ["--transport=streamablehttp", "http://localhost:8080/mcp"]
    }
  }
}
```

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

## Ingesting traffic

#### TLDR

```
sudo tcpdump -n --immediate-mode -s 65535 -U -w - | nc localhost 9999
# or
dumpcap -i eth0 -w - -F pcap  | nc localhost 9999
```

#### Long explanation

The `ingestor` service listens for incoming TCP connection, then reads PCAP data from the connection and creates PCAPs that are then processed by the assembler service and suricata.

You can configure the

- listen interface
- rotation interval

in the `.env` file.

The higher the rotation interval, the more delay there will be before the traffic is visible in Tulip. The default is 30 sec, which should be sufficient for most CTFs.

> [!WARN]
> The assembler maintains the state of TCP connections for only one PCAP file at a time. Therefore, if the rotation interval is set too low, the assembler might fail to correlate packets into a coherent flow.

See [DEVELOPMENT.md](DEVELOPMENT.md) for more information on the internal workings of Tulip.

## Suricata synchronization

#### TLDR: Modify `suricata.rules` and profit!

#### Long explanation

Suricata is already configured as a docker service in the `docker-compose.yml` file. It will read the `suricata.rules` file in the root of the Tulip directory and will generate alerts based on the rules defined there. The `enhancer` service will then read these alerts and match them to the flows in Tulip, adding tags to mongodb.

Sessions with matched alerts will be highlighted in the front-end and include which rule was matched.

See [DEVELOPMENT.md](DEVELOPMENT.md) for more information on the internal workings of Tulip.

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

## Security

Your Tulip instance will probably contain sensitive CTF information, like flags stolen from your machines. If you expose it to the internet and other people find it, you risk losing additional flags. It is recommended to host it on an internal network (for instance behind a VPN) or to put Tulip behind some form of authentication.

## Contributing

If you have an idea for a new feature, bug fixes, UX improvements, or other contributions, feel free to open a pull request or create an issue!
When opening a pull request, please target the `devel` branch.

## License

This project follows the [REUSE 3.3](https://reuse.software/spec-3.3/) specification. If not otherwise noted, all files in this repository are licensed under the [GPL-3.0-only](https://spdx.org/licenses/GPL-3.0-only.html) license.

## Credits

Tulip was initially written by [@RickdeJager](https://github.com/rickdejager) and [@Bazumo](https://github.com/bazumo), with additional help from [@Sijisu](https://github.com/sijisu).
Thanks to our fellow Team Europe players and coaches for testing, feedback and suggestions. Finally, thanks to the team behind [flower](https://github.com/secgroup/flower) for opensourcing their tooling.
