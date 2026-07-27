# Welcome to DreamingOS

[简体中文](README.md)

DreamingOS is an OpenWrt-based router operating system focused on a coherent
management experience, visible network state, and practical controls for modern
homes and small networks.

The project is continuously developed on top of the official OpenWrt source tree.
DreamingOS uses the complete, standalone `dreamingwrt-web` management interface
instead of legacy LuCI applications or themes. Its goal is to make the Web console,
control services, network model, system updates, and optional applications feel like
one consistent product.

The first public release is **26.07.1**.

> **Important:** The `dev` branch is for developers and early adopters only. Please
> install it inside a virtual machine such as PVE or ESXi. Test builds may fail in
> unpredictable ways, so proceed with caution. Development is ongoing and features
> will come online gradually — stay tuned.

## Preview

The screenshots below are from the DreamingOS console under development. The final
interface may differ from what is shown here.

![DreamingOS console preview 1](docs/screenshots/demo-1.jpg)
![DreamingOS console preview 2](docs/screenshots/demo-2.jpg)
![DreamingOS console preview 3](docs/screenshots/demo-3.jpg)
![DreamingOS console preview 4](docs/screenshots/demo-4.jpg)
![DreamingOS console preview 5](docs/screenshots/demo-5.jpg)
![DreamingOS console preview 6](docs/screenshots/demo-6.jpg)
![DreamingOS console preview 7](docs/screenshots/demo-7.jpg)

## Why DreamingOS

DreamingOS started with a simple requirement: a router should clearly explain what it
is doing, configuration changes should be understandable, and routine network
management should feel like one product rather than a collection of unrelated pages
and configuration files.

Current development areas include:

- a unified DreamingOS Web management interface;
- structured system and network APIs provided by DreamingOS control services;
- dashboard, terminal, topology, line-health, routing, logging, notifications, and
  system-management workflows;
- transactional configuration, capability reporting, operation auditing, and
  recovery;
- an x86_64 baseline using glibc and a recent Linux kernel;
- native applications and extensions that will be opened gradually.

Not every backend capability above is included in the first public release.
`dreamingwrt-web` is published as one complete component rather than split by page.
Capabilities that are not public yet or require private data report an explicit
unavailable or degraded state. The release does not use empty packages or pretend
that unavailable features are working.

## Current Status

DreamingOS is under active development. **26.07.1** is an early source release for
developers and testers. Ahead of the formal release we are still settling the initial
package set, the dependency boundary, and which installation methods are supported.

Interfaces, package boundaries, and upgrade procedures may still change. Each release will document verified capabilities and known limitations
instead of hiding unfinished work behind a generic stability claim.

DreamingOS currently supports Linux 7.2, which has not reached a final upstream
release. This kernel line will remain on the `dev` branch and track newer kernels.

The planned `stable` branch will use Linux 6.18 LTS. This is maintained by one person.
AI can help, but it cannot maintain a repository without human review, so limitations
are expected, particularly on the `dev` branch.

DreamingOS uses a completely new Web service. As a result, **all** `luci-app-*`
packages built for standard OpenWrt cannot run directly inside the DreamingOS Web
interface.

A later release is planned to add an OpenWrt compatibility layer that serves the
native OpenWrt Web interface on a separate port.

### Web access ports

The DreamingOS console and the native OpenWrt Web use different ports and do not
interfere with each other:

- **Native OpenWrt Web (uhttpd / LuCI):** port `80`. If the stock OpenWrt Web is still
  present on the system, reach it at `http://<device-ip>`.
- **DreamingOS console:** port `12517`, reachable directly at `http://<device-ip>:12517`.
  DreamingOS is also served through a reverse proxy on port `80` for paths such as
  `/app/` and `/login/`, so entering via port `80` does not conflict with LuCI.

The default login address is `http://192.168.1.1:12517`; change the password right
after the first login.

## Initial Public Scope

The first public release follows the official OpenWrt source layout. In addition to
the audited DreamingOS components under `package/lester/`, the repository contains
the Linux 7.2, glibc, networking-service, and build-system patches required by the
project.

| Component | Role | 26.07.1 status |
| --- | --- | --- |
| OpenWrt system changes | Linux 7.2-rc3, glibc 2.43, GCC 16, and base-package compatibility | **Included** |
| JMX kernel patches | Conntrack state, traffic control, multi-WAN lifecycle, and flow-offload isolation | **Included** |
| PPP and IPv6 service patches | Synchronized PPPoE multi-dial authentication and static DHCPv6 IA-PD | **Included; IA-PD remains early** |
| `dreamingwrt-web` | Complete standalone DreamingOS management interface | **Included as one complete component** |
| `jmxd` | System control, APIs, and supporting services | **Included; private-data features degrade by default** |
| `jmx` | Kernel-side network and traffic-control integration | **Included** |
| `libjmx_common` | Shared interfaces used by JMX components | **Included** |
| `dreamingproxy` | Native proxy and egress-policy application | **Not included in 26.07.1** |

The `dreamingproxy` package source is not in this repository. `jmxd` still carries its
service slot, API routes and permission definitions, all disabled by default; without
the package those endpoints report unavailable and nothing else is affected.

The repository tree and the [26.07.1 release notes](CHANGELOG.md) are authoritative.

## What Is Not Included

The public repository does not contain private or redistribution-restricted
databases, rules, or libraries. In particular, the first release excludes:

- the private DPI and application-signature corpus;
- the device-fingerprint corpus;
- device/brand image libraries and unverified bundled UniFi Setup media;
- internal rule-generation materials and data-processing assets;
- `dreamingproxy` and its runtime components;
- legacy `luci-app-*`, `luci-theme-*`, and the historical LuCI console;
- third-party packages whose provenance and licenses have not been reviewed.

Public components build without these assets. Related capabilities are disabled or
degraded explicitly instead of failing to link, crashing at startup, or leaving
unusable pages behind.

## Building

The current development baseline is x86_64, glibc 2.43, and Linux 7.2-rc3. Release
`26.07.1` is an early source release and still requires you to choose an appropriate
firmware target configuration. Private DPI, fingerprint, and image libraries are not
bundled by default.

### Notes

1. **Do not build as root.**
2. Users in mainland China should prepare reliable access to upstream source hosts.
3. The default login address is `http://192.168.1.1:12517` and the password is
   `password`. Change the password immediately after the first login.

### Linux

Install Debian or Ubuntu LTS, then install the build dependencies:

```bash
sudo apt update -y
sudo apt full-upgrade -y
sudo apt install -y ack antlr3 asciidoc autoconf automake autopoint binutils bison build-essential \
bzip2 ccache clang cmake cpio curl device-tree-compiler flex gawk gcc-multilib g++-multilib gettext \
genisoimage git gperf haveged help2man intltool libc6-dev-i386 libelf-dev libfuse-dev libglib2.0-dev \
libgmp3-dev libltdl-dev libmpc-dev libmpfr-dev libncurses5-dev libncursesw5-dev libpython3-dev \
libreadline-dev libssl-dev libtool llvm lrzsz libnsl-dev ninja-build p7zip p7zip-full patch pkgconf \
python3 python3-pyelftools python3-setuptools qemu-utils rsync scons squashfs-tools subversion \
swig texinfo uglifyjs upx-ucl unzip vim wget xmlto xxd zlib1g-dev
```

Clone, update feeds, and configure the target:

```bash
git clone https://github.com/Lester0504/DreamingOS.git
cd DreamingOS
./scripts/feeds update -a
./scripts/feeds install -a
make menuconfig
```

Download sources and build. `-j` is the thread count; use a single thread for the
first diagnostic build:

```bash
make download -j8
make V=s -j1
```

You may use the source freely under its applicable licenses. Please reference this
GitHub repository when redistributing a source-built firmware image. This is a
request, not a license term.

For later rebuilds:

```bash
cd DreamingOS
git pull
./scripts/feeds update -a
./scripts/feeds install -a
make defconfig
make download -j8
make V=s -j$(nproc)
```

To start configuration again:

```bash
rm -rf .config
make menuconfig
make V=s -j$(nproc)
```

Firmware output is written under `bin/targets`.

### WSL/WSL2

Windows paths containing spaces can break the build. Prefix `make` with:

```bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

OpenWrt requires a case-sensitive filesystem. If the build check reports:

```txt
Build dependency: OpenWrt can only be built on a case-sensitive filesystem
```

create a repository directory and enable case sensitivity before cloning:

```powershell
# Run the terminal as Administrator
PS > fsutil.exe file setCaseSensitiveInfo <your_local_dreamingos_path> enable
PS > git clone https://github.com/Lester0504/DreamingOS.git <your_local_dreamingos_path>
```

Running `fsutil.exe` after cloning is insufficient because the setting only affects
new file changes.

### Native macOS

1. Install Xcode from the App Store.
2. Install Homebrew:

   ```bash
   /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
   ```

3. Install the toolchain and dependencies:

   ```bash
   brew unlink awk
   brew install coreutils diffutils findutils gawk gnu-getopt gnu-tar grep make ncurses pkg-config wget quilt xz
   brew install gcc@11
   ```

4. Add GNU tools to your path. On Intel Macs:

   ```bash
   echo 'export PATH="/usr/local/opt/coreutils/libexec/gnubin:$PATH"' >> ~/.bashrc
   echo 'export PATH="/usr/local/opt/findutils/libexec/gnubin:$PATH"' >> ~/.bashrc
   echo 'export PATH="/usr/local/opt/gnu-getopt/bin:$PATH"' >> ~/.bashrc
   echo 'export PATH="/usr/local/opt/gnu-tar/libexec/gnubin:$PATH"' >> ~/.bashrc
   echo 'export PATH="/usr/local/opt/grep/libexec/gnubin:$PATH"' >> ~/.bashrc
   echo 'export PATH="/usr/local/opt/gnu-sed/libexec/gnubin:$PATH"' >> ~/.bashrc
   echo 'export PATH="/usr/local/opt/make/libexec/gnubin:$PATH"' >> ~/.bashrc
   ```

   On Apple silicon Macs:

   ```zsh
   echo 'export PATH="/opt/homebrew/opt/coreutils/libexec/gnubin:$PATH"' >> ~/.bashrc
   echo 'export PATH="/opt/homebrew/opt/findutils/libexec/gnubin:$PATH"' >> ~/.bashrc
   echo 'export PATH="/opt/homebrew/opt/gnu-getopt/bin:$PATH"' >> ~/.bashrc
   echo 'export PATH="/opt/homebrew/opt/gnu-tar/libexec/gnubin:$PATH"' >> ~/.bashrc
   echo 'export PATH="/opt/homebrew/opt/grep/libexec/gnubin:$PATH"' >> ~/.bashrc
   echo 'export PATH="/opt/homebrew/opt/gnu-sed/libexec/gnubin:$PATH"' >> ~/.bashrc
   echo 'export PATH="/opt/homebrew/opt/make/libexec/gnubin:$PATH"' >> ~/.bashrc
   ```

5. Run `source ~/.bashrc`, then enter `bash` and use the same build commands as on
   Linux.

## Versioning

DreamingOS releases use `YY.MM.N`:

- `YY`: two-digit release year;
- `MM`: two-digit release month;
- `N`: the sequential release number within that month.

For example, `26.07.1` is the first release in July 2026. Git tags use a `v` prefix,
such as `v26.07.1`.

## Contributing

Once the repository is public, reproducible bug reports and focused pull requests are
welcome. Include the affected release, target platform, reproduction steps, relevant
configuration with sensitive values removed, and concise logs around the failure.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the complete requirements. Bug, feature,
and pull-request templates are included in the repository.

## Security

Do not publish credentials, private keys, complete configuration backups, packet
captures containing private traffic, or other sensitive device data in a public
issue. Follow [SECURITY.md](SECURITY.md) to report a vulnerability privately.

## Upstream and Credits

DreamingOS is built on [OpenWrt](https://openwrt.org/) and benefits from the work of
the OpenWrt community and its many upstream open-source projects.

Thanks to [fanchmwrt/fanchmwrt](https://github.com/fanchmwrt/fanchmwrt). Parts of the
DreamingOS DPI components are derived from code in that repository, and the relevant
derived files retain the original author notices.

DreamingOS is an independent project and is not an official OpenWrt release.
Third-party notices and component-specific licenses remain with their respective
source code.

## License

This is a multi-license source tree. The OpenWrt baseline and third-party components
remain under their respective licenses. DreamingOS-owned components identify their
licenses in the corresponding source and package metadata. See [COPYING](COPYING) and
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## Maintainer Note

ChatGPT contributed more than 90% of the code in this project, so please blame it
when you find a bug. (Just kidding.)

DreamingOS began as an experiment: I wanted to use AI to reduce product development
time by more than 95% while preserving as much quality as possible.

I wanted to address pain points in existing OpenWrt distributions. DreamingOS grew
out of `luci-theme-argon`, a theme I liked enough to modify heavily with Liquid Glass
and some deliberately flashy effects. Legacy LuCI pages, however, carry a great deal
of historical baggage, and adapting everything around them caused other plugins to
render incorrectly.

That was when I started building DreamingOS. I moved away completely from OpenWrt's
traditional Web pages and interaction model, rebuilt the management interface, and
wrote the backend it needed.

Someone once asked: what is the point of making a router console look good when you
do not spend your time looking at it?

My answer is that DreamingOS is not merely "good-looking." Everyone defines beauty
differently, and I do not expect everyone to agree that it looks good. I want to
bring you a router whose interaction and operating logic feel as comfortable as I
can make them.

It combines traffic control, DPI, auditing, and an AI agent. I hope it can lower the
barrier to exploring and using routers. An iOS application is also in development
and will be open-sourced in my repositories when it is ready.

This is a genuine "AI router," and more interesting ideas are in preparation.

(There is an Easter egg in this project, but I doubt anyone will find it.)

Finally, for several reasons, the complete DPI and device-fingerprint databases will
not be released in the first few versions, although the corresponding code is open.

Enjoy!
