FROM ubuntu:22.04

ENV VERSION=3.4.0
ENV PACKAGE=ouistiti
ARG BRANCH=${PACKAGE}-${VERSION}
ARG DEBIANDIR=${PACKAGE}/packages

RUN apt update
ENV TZ=Europe/London
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

RUN apt update && apt install -y \
	libsqlite3-dev \
	libjansson-dev \
	libconfig-dev \
	libssl-dev \
	debhelper \
	devscripts

RUN apt update && apt install -y \
	python3 \
	libpython3-dev \
	python3-dev 

RUN apt update && apt install -y \
	wget

RUN git clone https://github.com/ouistiti-project/ouistiti -b ${BRANCH} && \
	cd ${PACKAGE} && \
	git submodule init && git submodule update && \
	tar -C .. -czf ../${PACKAGE}_${VERSION}.orig.tar.gz --exclude=packages --exclude=.git* --exclude=*sonarcloud* --exclude=.travis.yml ${PACKAGE}

RUN mkdir /tmp/debian

ADD . /tmp/debian/

RUN tar -C ${DEBIANDIR} -czf ../debian.tar.gz debian

RUN rm -rf ${PACKAGE} && \
	tar -xf ${PACKAGE}_${VERSION}.orig.tar.gz && \
	cd ${PACKAGE} && \
	tar -xf ../debian.tar.gz && \
	sed -i 's,datadir=/srv/www,,g' debian/rules && \
	export LDFLAGS=-pthread && \
	debuild -i -uc -us || \
	cat /tmp/ouistiti_3.4.0-1.diff*

VOLUME ["/mnt"]
#CMD bash
CMD cp *.deb *.orig.tar.gz /mnt/ && echo "Found DEB files into packages directory"
