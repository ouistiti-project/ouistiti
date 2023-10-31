FROM fedora:latest

ENV VERSION=3.4.0
ENV PACKAGE=ouistiti
ARG BRANCH=${PACKAGE}-${VERSION}
ARG SPECDIR=/root/rpmbuild

RUN dnf -y update && dnf -y install \
	sqlite-devel \
	jansson-devel \
	libconfig-devel \
	openssl-devel \
	fedora-packager \
	rpmdevtools \
	gcc \
	make

RUN dnf -y update && dnf -y install \
	python3 \
	python3-devel

RUN dnf -y update && dnf -y install \
	wget

VOLUME ["/mnt"]

ADD ./ouistiti.spec /tmp/

RUN git clone https://github.com/ouistiti-project/ouistiti -b ${BRANCH} ${PACKAGE}-${VERSION} && \
	cd ${PACKAGE}-${VERSION} && \
	git submodule init && git submodule update

ADD jquery-3.6.0.min.js ${PACKAGE}-${VERSION}/www/

RUN tar -C .. -czf ../${PACKAGE}-${VERSION}.tar.gz --exclude=packages --exclude=.git* --exclude=*sonarcloud* --exclude=.travis.yml ${PACKAGE}-${VERSION} && \
	tar -tf ../${PACKAGE}-${VERSION}.tar.gz

RUN mkdir -p /root/rpmbuild && \
	cp ${PACKAGE}-${VERSION}/packages/rpmbuild/ouistiti.spec /root/rpmbuild

RUN rm -rf ${PACKAGE}-${VERSION} && \
	mkdir -p /root/rpmbuild/BUILD/ && \
	mkdir -p /root/rpmbuild/SOURCES/ && \
	mv ${PACKAGE}-${VERSION}.tar.gz /root/rpmbuild/SOURCES/

RUN ls /root/rpmbuild && rpmbuild -ba ${SPECDIR}/ouistiti.spec

CMD cp /root/rpmbuild/RPMS/*/*.rpm /root/rpmbuild/SRPMS/*.rpm /root/rpmbuild/SOURCES/*.tar.gz /mnt
