#!/bin/sh

SCRIPTDIR=$(dirname $0)
make -C $SCRIPTDIR -f certificate.mk generate
