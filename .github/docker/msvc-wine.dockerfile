# Cross-compiles Windows kernel drivers using msvc-wine.
# Toolchain: MSVC 18.0 + SDK/WDK 10.0.22621
# Architectures: x86, x64, ARM, ARM64
FROM alpine:3.21 AS msvc-wine
RUN apk add --no-cache git
RUN git clone https://github.com/mcha-forks/msvc-wine.git /msvc-wine \
    && cd /msvc-wine && git checkout 2d5f5a3

FROM registry.fedoraproject.org/fedora-minimal:44 AS wine

COPY <<-'EOF' /etc/yum.repos.d/_copr:copr.fedorainfracloud.org:mochaa:wine.repo
	[copr:copr.fedorainfracloud.org:mochaa:wine]
	name=Copr repo for wine owned by mochaa
	baseurl=https://download.copr.fedorainfracloud.org/results/mochaa/wine/fedora-$releasever-$basearch/
	type=rpm-md
	skip_if_unavailable=True
	gpgcheck=1
	gpgkey=https://download.copr.fedorainfracloud.org/results/mochaa/wine/pubkey.gpg
	repo_gpgcheck=0
	enabled=1
	enabled_metadata=1

	[copr:copr.fedorainfracloud.org:mochaa:wine:ml]
	name=Copr repo for wine owned by mochaa (i386)
	baseurl=https://download.copr.fedorainfracloud.org/results/mochaa/wine/fedora-$releasever-i386/
	type=rpm-md
	skip_if_unavailable=True
	gpgcheck=1
	gpgkey=https://download.copr.fedorainfracloud.org/results/mochaa/wine/pubkey.gpg
	repo_gpgcheck=0
	cost=1100
	enabled=1
	enabled_metadata=1
EOF

RUN <<-EOF
	set -xeu
	microdnf install -y wine-core wine-core.i686 wine-mono
	microdnf clean all
EOF

RUN <<-EOF
	set -xeu
	wine wineboot -u
	wine reg.exe add HKCU\\Software\\Wine\\Drivers /v Graphics /t REG_SZ /d null
	wineserver -w
EOF

WORKDIR /builddir

FROM wine AS fetch-wdk
COPY --from=msvc-wine /msvc-wine/wdk-download.sh ./
RUN WINEDEBUG=1 bash -x ./wdk-download.sh --cache wdk https://go.microsoft.com/fwlink/?linkid=2330411

FROM python:3.14-slim AS fetch-msvc
WORKDIR /builddir
COPY --from=msvc-wine /msvc-wine/vsdownload.py ./
RUN PYTHONUNBUFFERED=1 ./vsdownload.py --accept-license --only-download --cache cache \
    --major=18 --msvc-version=18.0 --sdk-version=10.0.22621 --with-wdk-installer wdk/Installers \
    Microsoft.Component.MSBuild

FROM wine AS builder
RUN <<-EOF
	microdnf install -y msitools perl
	microdnf clean all
EOF
COPY --from=fetch-msvc /builddir/cache/ ./cache/
COPY --from=fetch-wdk /builddir/wdk/Installers/ ./wdk/Installers/
COPY --from=msvc-wine /msvc-wine/vsdownload.py ./
COPY --from=msvc-wine /msvc-wine/patches/ ./patches/
RUN PYTHONUNBUFFERED=1 python3 ./vsdownload.py --accept-license --cache cache --dest /opt/msvc \
    --major=18 --msvc-version=18.0 --sdk-version=10.0.22621 --with-wdk-installer wdk/Installers \
    Microsoft.Component.MSBuild
COPY --from=msvc-wine /msvc-wine/lowercase /msvc-wine/fixinclude /msvc-wine/install.sh /msvc-wine/msvctricks.cpp ./
COPY --from=msvc-wine /msvc-wine/wrappers/ ./wrappers/
RUN bash -x ./install.sh /opt/msvc

FROM wine
COPY --from=builder /opt/msvc /opt/msvc
