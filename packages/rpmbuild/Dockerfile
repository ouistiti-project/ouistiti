FROM fedora:latest

ENV VERSION=3.6.0
ENV PACKAGE=ouistiti
ENV USER=builder
ARG BRANCH=${PACKAGE}-${VERSION}
ARG DEBIANDIR=${PACKAGE}/packages
ARG REPOSITORY=https://github.com/ouistiti-project/ouistiti
ARG SPECDIR=/home/$USER/rpmbuild

ENV BRANCH=${BRANCH} \
    REPOSITORY=${REPOSITORY}


RUN dnf -y update && dnf -y install \
	sqlite-devel \
	jansson-devel \
	libconfig-devel \
	openssl-devel \
	python3 \
	python3-devel \
	gcc \
	make \
	wget

RUN dnf -y update && dnf -y install \
	rpmdevtools \
	fedora-packager

ENV SPECDIR=${SPECDIR}
ADD ./ouistiti.spec /tmp/

RUN useradd -m -s /bin/bash $USER
RUN chown -R $USER:$USER /tmp
USER $USER
WORKDIR /home/$USER
RUN mkdir -p ${SPECDIR}
RUN mkdir -p /tmp/out

USER root
RUN cat > /home/$USER/build.sh << 'EOF'
#!/bin/bash
set -e

echo "Cloning"
# generate source package
git clone ${REPOSITORY} -b ${BRANCH} ${PACKAGE}-${VERSION}
cd ${PACKAGE}-${VERSION}
if [ -d ${REPOSITORY}/libhttpserver/.git ]; then
 git clone ${REPOSITORY}/libhttpserver/ libhttpserver
else
 git submodule init && git submodule update
fi

cd ..
tar -czf ${PACKAGE}-${VERSION}.tar.gz \
	--exclude=packages --exclude=.git* \
	--exclude=*sonarcloud* \
	--exclude=.travis.yml \
	${PACKAGE}-${VERSION}

mkdir -p ${SPECDIR}
cp /tmp/ouistiti.spec ${SPECDIR}

rm -rf ${PACKAGE}-${VERSION}
mkdir -p ${SPECDIR}/BUILD/
mkdir -p ${SPECDIR}/SOURCES/
mv ${PACKAGE}-${VERSION}.tar.gz ${SPECDIR}/SOURCES/

rpmbuild -ba ${SPECDIR}/ouistiti.spec

cp ${SPECDIR}/RPMS/*/*.rpm ${SPECDIR}/SRPMS/*.rpm ${SPECDIR}/SOURCES/*.tar.gz /tmp/out
EOF

RUN chmod +x /home/$USER/build.sh && chown $USER:$USER /home/$USER/build.sh

USER $USER

ENTRYPOINT ["/home/$USER/build.sh"]
