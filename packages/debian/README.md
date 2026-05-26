# Building the Debian package for ouistiti

## Prerequisites

Install the required build dependencies:

```shell
apt-get install debhelper devscripts libconfig-dev libjansson-dev \
                libsqlite3-dev libssl-dev libpython3-dev
```

## Manual build

1. Copy the `packages/debian` directory into the root of the ouistiti source tree:

```shell
cp -r packages/debian debian
```

2. Create the original source archive from the parent directory:

```shell
cd ..
tar -czf ouistiti_3.6.0.orig.tar.gz \
    --exclude=ouistiti/packages --exclude=ouistiti/.git* \
    ouistiti
cd ouistiti
```

3. Build the package:

```shell
export LDFLAGS=-pthread
debuild -i -uc -us
```

The `.deb` files are generated in the parent directory.

## Docker build

Build and extract the packages using the provided Dockerfile:

```shell
cd packages/debian
mkdir -p out
docker build -t ouistiti-builder .
docker run --rm -v $(pwd)/out:/tmp/out ouistiti-builder
```

The `.deb` and `.orig.tar.gz` files will be copied into `packages/debian/out/`.

## Generated packages

| Package | Contents |
|---|---|
| `ouistiti` | Server binary, all modules (auth, MFA, forward, signature, webstream, ...) |
| `ouistiti-dev` | Headers, unversioned `.so` symlinks, pkg-config file |
| `ouistiti-utils` | Tools (streamer, TOTP generator, WebApp samples), Python module |
