# inherited
VERSION?=	unknown
OPENSSL?=	openssl
MKDIR?=		mkdir

# OpenSSL settings
CA_SUBJECT?=	'/C=CH/O=SSLsplit Root CA/CN=SSLsplit Root CA/'
CA_DAYS?=	1095
CA_EXT:=	v3_ca
CRT_SUBJECT?=	'/C=CH/O=SSLsplit Test Certificate/CN=daniel.roe.ch/'
CRT_DAYS?=	365
CRT_EXT:=	v3_crt
CONFIG:=	x509v3ca.cnf
PASSWORD:=	test
DIGEST:=	-$(shell echo test | $(OPENSSL) dgst -sha256 2>/dev/null | grep -q f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2 && echo sha256 || echo sha1)
NO_SSL2:=	$(shell $(OPENSSL) s_server -h 2>&1|awk '/-no_ssl2/ {print $$1}')

all: rsa dsa ec targets server pwd

testreqs: rsa targets server session

session: session.pem

dh: dh512.param dh1024.param dh2048.param dh4096.param

rsa: rsa.pem

pwd: pwd.key

dsa: dsa.pem

ec: ec.pem

server: server.pem

dh512.param:
	$(OPENSSL) dhparam -out $@ -2 512

dh1024.param:
	$(OPENSSL) dhparam -out $@ -2 1024

dh2048.param:
	$(OPENSSL) dhparam -out $@ -2 2048

dh4096.param:
	$(OPENSSL) dhparam -out $@ -2 4096

dsa.param:
	$(OPENSSL) dsaparam -out $@ 1024

dsa.key: dsa.param
	$(OPENSSL) gendsa -out $@ $<

rsa.key:
	$(OPENSSL) genrsa -out $@ 2048

pwd.key: rsa.key
	echo $(PASSWORD) | $(OPENSSL) rsa -in $< -out $@ -aes128 -passout stdin

ec.key:
	$(OPENSSL) ecparam -out $@ -name prime192v1 -genkey

%.crt: %.key $(CONFIG)
	$(OPENSSL) req -new -nodes -x509 $(DIGEST) -out $@ -key $< \
		-config $(CONFIG) -extensions $(CA_EXT) \
		-subj $(CA_SUBJECT) \
		-set_serial 1 -days $(CA_DAYS)

server.key:
	$(OPENSSL) genrsa -out $@ 2048

server.crt: server.key $(CONFIG)
	$(OPENSSL) req -new -nodes -x509 $(DIGEST) -out $@ -key $< \
		-config $(CONFIG) -extensions $(CRT_EXT) \
		-subj $(CRT_SUBJECT) \
		-set_serial 42 -days $(CRT_DAYS)

%.pem: %.crt %.key
	cat $^ >$@

targets: targets/daniel.roe.ch.pem targets/wildcard.roe.ch.pem
	$(RM) rsa.srl

targets/daniel.roe.ch.pem: rsa.crt
	$(MKDIR) -p targets
	$(OPENSSL) genrsa -out targets/daniel.roe.ch.key 2048
	$(OPENSSL) req -new $(DIGEST) -subj '/C=CH/CN=daniel.roe.ch/' \
		-key targets/daniel.roe.ch.key \
		-out targets/daniel.roe.ch.csr
	$(OPENSSL) x509 -req $(DIGEST) -CAcreateserial -days 365 \
		-CA rsa.crt -CAkey rsa.key \
		-in targets/daniel.roe.ch.csr \
		-out targets/daniel.roe.ch.crt
	cat targets/daniel.roe.ch.crt targets/daniel.roe.ch.key rsa.crt \
		>targets/daniel.roe.ch.pem
	$(RM) targets/daniel.roe.ch.key targets/daniel.roe.ch.csr \
		targets/daniel.roe.ch.crt

targets/wildcard.roe.ch.pem: rsa.crt
	$(MKDIR) -p targets
	$(OPENSSL) genrsa -out targets/wildcard.roe.ch.key 2048
	$(OPENSSL) req -new $(DIGEST) -subj '/C=CH/CN=*.roe.ch/' \
		-key targets/wildcard.roe.ch.key \
		-out targets/wildcard.roe.ch.csr
	$(OPENSSL) x509 -req $(DIGEST) -CAcreateserial -days 365 \
		-CA rsa.crt -CAkey rsa.key \
		-in targets/wildcard.roe.ch.csr \
		-out targets/wildcard.roe.ch.crt
	cat targets/wildcard.roe.ch.crt targets/wildcard.roe.ch.key rsa.crt \
		>targets/wildcard.roe.ch.pem
	$(RM) targets/wildcard.roe.ch.key targets/wildcard.roe.ch.csr \
		targets/wildcard.roe.ch.crt

# localhost network connectivity is required
session.pem: | server.pem
	$(OPENSSL) s_server -accept 46143 -cert server.pem -quiet $(NO_SSL2) & \
		pid=$$! ; \
		sleep 1 ; \
		echo q | $(OPENSSL) s_client -connect 127.0.0.1:46143 \
			-quiet -no_ign_eof -sess_out $@ ; \
		kill $$pid
	test -r $@

clean:
	rm -rf rsa.* dsa.* ec.* dh*.param targets *.srl server.*

.PHONY: all clean rsa dsa ec dh session targets

.PRECIOUS: %.pem %.crt %.key %.param

