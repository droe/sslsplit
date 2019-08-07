#!/bin/sh
if [ -z "$SSL" ]; then
	echo '$SSL not set, aborting' >&2
	exit 1
fi
if [ -z "$EVENT" ]; then
	echo '$EVENT not set, aborting' >&2
	exit 1
fi

case "$SSL" in
openssl-0.9.*)
	SSLURL=https://www.openssl.org/source/old/0.9.x/$SSL.tar.gz
	;;
openssl-1.0.0*)
	SSLURL=https://www.openssl.org/source/old/1.0.0/$SSL.tar.gz
	;;
openssl-1.0.1*)
	SSLURL=https://www.openssl.org/source/old/1.0.1/$SSL.tar.gz
	;;
openssl-*)
	SSLURL=https://www.openssl.org/source/$SSL.tar.gz
	;;
libressl-*)
	#SSLURL=https://ftp.openbsd.org/pub/OpenBSD/LibreSSL/$SSL.tar.gz
	SSLURL=http://ftp.fau.de/pub/OpenBSD/LibreSSL/$SSL.tar.gz
	;;
*)
	exit 1
	;;
esac

case "$EVENT" in
libevent-2.1.8)
	EVENTURL=https://github.com/libevent/libevent/releases/download/release-2.1.8-stable/libevent-2.1.8-stable.tar.gz
	EVENTPATCH=Mk/patches/libevent-2.1.8.diff
	EVENTOPTS="$EVENTOPTS --disable-libevent-regress --disable-samples"
	;;
libevent-2.1.11)
	EVENTURL=https://github.com/libevent/libevent/releases/download/release-2.1.11-stable/libevent-2.1.11-stable.tar.gz
	EVENTOPTS="$EVENTOPTS --disable-libevent-regress --disable-samples"
	;;
libevent-2.0.22)
	EVENTURL=https://github.com/libevent/libevent/releases/download/release-2.0.22-stable/libevent-2.0.22-stable.tar.gz
	;;
*)
	exit 1
	;;
esac

if [ ! -d "$HOME/opt/$SSL" ]; then
	if [ "`uname`" = "Linux" ]; then
		SSLOPTS="$SSLOPTS -Wl,-rpath=$HOME/opt/$SSL/lib"
	fi
	wget "$SSLURL" || exit 1
	tar -xzvf "$SSL.tar.gz" || exit 1
	cd "$SSL" || exit 1
	./config shared \
		--prefix="$HOME/opt/$SSL" \
		--openssldir="$HOME/opt/$SSL" \
		$SSLOPTS || exit 1
	make && make install || { rm -rf "$HOME/opt/$SSL"; exit 1; }
	cd ..
fi

export CPPFLAGS="-I$HOME/opt/$SSL/include"
export LDFLAGS="-L$HOME/opt/$SSL/lib"

if [ ! -d "$HOME/opt/$EVENT" ]; then
	wget "$EVENTURL" || exit 1
	tar -xzvf "$EVENT-stable.tar.gz" || exit 1
	cd "$EVENT-stable" || exit 1
	if [ -n "$EVENTPATCH" ]; then
		patch -p0 < ../$EVENTPATCH || exit 1
	fi
	./configure --prefix="$HOME/opt/$EVENT" $EVENTOPTS || exit 1
	make && make install || { rm -rf "$HOME/opt/$EVENT"; exit 1; }
	cd ..
fi

