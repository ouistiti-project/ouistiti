package=ouistiti
version=$(shell grep '^version[?,:, ]*=' ../Makefile | awk 'BEGIN{FS="="}{print $$2}')
SPECFILE:=./rpmbuild/ouistiti.spec

RPMDIR=$(HOME)
UID=$(shell id -u)

.PHONY: FORCE

debian: FORCE
	@debuild --no-sign

$(RPMDIR)/rpmbuild/SOURCES:
	@mkdir -p $@

$(RPMDIR)/rpmbuild/SOURCES/$(package)-$(version).tar.gz: $(RPMDIR)/rpmbuild/SOURCES
	@make -C .. clean
	@tar -cz --exclude=.git --exclude=.config* --exclude=package --exclude=rpmbuild .. > $@

rpm: $(RPMDIR)/rpmbuild/SOURCES/$(package)-$(version).tar.gz FORCE
	@rpmbuild -ba $(SPECFILE)

DOCKERFILE:=docker/Dockerfile
DOCKERTARGET:=ouistitiproject/$(package)
docker/libouistiti_latest_amd64.deb: URL=$(shell  wget https://api.github.com/repos/ouistiti-project/libhttpserver/releases/latest -q -O - | awk '/browser_download_url/{print $$2}')
docker/libouistiti_latest_amd64.deb:
	@echo "  "WGET $@
	@wget $(URL) -O $@
docker/ouistiti_latest_amd64.deb: URL=$(shell  wget https://api.github.com/repos/ouistiti-project/ouistiti/releases/latest -q -O - | awk '/browser_download_url/{print $$2}')
docker/ouistiti_latest_amd64.deb:
	@echo "  "WGET $@
	@wget $(URL) -O $@
docker-build: docker/libouistiti_latest_amd64.deb docker/ouistiti_latest_amd64.deb
	@docker build --file $(DOCKERFILE) --build-arg UID=$(UID) -t $(DOCKERTARGET) $(dir $(DOCKERFILE))

docker: FORCE
	@docker run --net=host -v $(PWD):/srv $(DOCKERTARGET)
