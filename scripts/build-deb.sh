#!/bin/bash

# helper script to be invoked by jenkins/buildbot or github actions

# $1 [optional]: the build type - release | nightly | test
buildtype=${1:-test}

set -x
set -e

PARALLEL=${PARALLEL:-1}
TMP=$(mktemp -d /tmp/debuild.XXXXXX)

function cleanup() {
  [[ -d $TMP ]] && rm -rf $TMP
}
trap cleanup EXIT

# populate submodules
git submodule update --init --recursive

. scripts/git-tag.sh

git archive HEAD --prefix=bcc/ --format=tar -o $TMP/bcc_$revision.orig.tar

# archive submodules
pushd src/cc/libbpf
git archive HEAD --prefix=bcc/src/cc/libbpf/ --format=tar -o $TMP/bcc_libbpf_$revision.orig.tar
popd

pushd $TMP

# merge all archives into bcc_$revision.orig.tar.gz
tar -A -f bcc_$revision.orig.tar bcc_libbpf_$revision.orig.tar
gzip bcc_$revision.orig.tar

tar xf bcc_$revision.orig.tar.gz
cd bcc

debuild=debuild
if [[ "$buildtype" = "test" ]]; then
  # when testing, use faster compression options
  debuild+=" --preserve-envvar PATH"
  echo -e '#!/bin/bash\nexec /usr/bin/dpkg-deb -z1 "$@"' \
    | sudo tee /usr/local/bin/dpkg-deb
  sudo chmod +x /usr/local/bin/dpkg-deb
  dch -b -v $revision-$release "$git_subject"
fi
if [[ "$buildtype" = "nightly" ]]; then
  dch -v $revision-$release "$git_subject"
fi

vendor=$(lscpu | grep Vendor | awk '{ print $3 }')
arch=$(dpkg --print-architecture)
release=$(cat /etc/os-release | grep VERSION_CODENAME | cut -d'=' -f2)

# Below debuild calls lintian which hangs within a Ubuntu focal docker image for
# arm64 running from amd64:
# https://bugs.launchpad.net/ubuntu/+source/lintian/+bug/1881217
# The problem comes from safe_qx() Perl function which asynchronously
# calls a command and which, for unknown reasons, never returns.
# NOTE This problem occurs on focal, not on bionic or groovy.
# NOTE This problem does not occur when running arm docker image on arm host.
# It only happens when cross building/running.
# WARNING So, we will deactivate lintian in this particular case.
# This is still run for bionic, so if there is any trouble, it should be throw
# in bionic too.
if [[ $vendor != 'ARM' && $arch = 'arm64' && $release = 'focal' ]]; then
	no_lintian='--no-lintian'
fi

DEB_BUILD_OPTIONS="nocheck parallel=${PARALLEL}" $debuild ${no_lintian} -us -uc
popd

cp $TMP/*.deb .
