FROM ubuntu:bionic-20210118

RUN apt update && apt install -y \
 libconfig9 \
 libmbedcrypto1 \
 libmbedtls10 \
 libjansson4 \
 libsqlite3-0

COPY ouistiti_latest_amd64.deb /tmp
RUN dpkg -i /tmp/ouistiti_latest_amd64.deb

COPY ouistiti.conf /etc/ouistiti
CMD ouistiti
