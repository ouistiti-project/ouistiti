package=ouistiti
version=$(shell grep '^version[?,:, ]*=' ../Makefile | awk 'BEGIN{FS="="}{print $$2}')
SPECFILE:=./rpmbuild/ouistiti.spec

RPMDIR=$(HOME)

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
