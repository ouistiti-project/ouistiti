FROM ubuntu:24.04

ENV VERSION=3.6.0
ENV PACKAGE=ouistiti
ENV USER=ubuntu
ARG BRANCH=${PACKAGE}-${VERSION}
ARG DEBIANDIR=${PACKAGE}/packages
ARG REPOSITORY=https://github.com/ouistiti-project/ouistiti

ENV BRANCH=${BRANCH} \
    REPOSITORY=${REPOSITORY}

RUN apt-get update
ENV TZ=Europe/London
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

RUN apt-get update && apt-get install -y \
	build-essential \
	libsqlite3-dev \
	libjansson-dev \
	libconfig-dev \
	libssl-dev \
	python3 \
	libpython3-dev \
	python3-dev \
	git \
	wget \
	vim

RUN apt-get update && apt-get install -y \
	chrpath \
	debhelper \
	devscripts

RUN mkdir -p /tmp/debian
ADD . /tmp/debian/

RUN mkdir -p /tmp/ouistiti

#RUN useradd -m -s /bin/bash $USER
RUN chown -R $USER:$USER /tmp
USER $USER
WORKDIR /home/$USER
RUN mkdir -p /tmp/out

USER root
RUN cat > /home/$USER/build.sh << 'EOF'
#!/bin/bash
set -e

echo "Cloning"
# generate source package
git clone ${REPOSITORY} -b ${BRANCH}
cd ${PACKAGE}
if [ -d ${REPOSITORY}/libhttpserver/.git ]; then
 git clone ${REPOSITORY}/libhttpserver/ libhttpserver
else
 git submodule init && git submodule update
fi
echo "Debian packaging"
cd packages
tar -czf ../../debian.tar.gz debian
cd ../..
ls
echo "Source packaging"
tar -czf ./${PACKAGE}_${VERSION}.orig.tar.gz \
	--exclude=packages --exclude=.git* \
	--exclude=*sonarcloud* --exclude=.travis.yml \
	${PACKAGE}

# build the package
echo "Cleanup"
rm -rf ${PACKAGE}
tar -xf ${PACKAGE}_${VERSION}.orig.tar.gz
cd ${PACKAGE}
tar -xf ../debian.tar.gz
echo "Build"
LDFLAGS=-pthread debuild -i -uc -us
echo "Copy"
cd ~
cp *.deb *.orig.tar.gz /tmp/out && echo "Found DEB files into packages directory"
EOF

RUN chmod +x /home/$USER/build.sh && chown $USER:$USER /home/$USER/build.sh

USER $USER

ENTRYPOINT ["/home/$USER/build.sh"]

