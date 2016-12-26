#!/bin/bash

set -ex
libtoolize --copy
aclocal
autoconf
autoheader
automake --add-missing --copy
