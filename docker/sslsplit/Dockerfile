FROM alpine:3.12.7 as builder
RUN apk add --no-cache fts libressl libevent libpcap libnet openssl
RUN apk add --no-cache libressl-dev libevent-dev libpcap-dev libnet-dev \
                       check-dev libc-dev fts-dev linux-headers gcc make git
WORKDIR /opt/sslsplit
COPY . .
ENV LIBS -lfts
ENV TCPPFLAGS -DDOCKER
RUN export SOURCE_DATE_EPOCH=$(stat -c '%Y' *.c *.h|sort -r|head -1); \
    make clean && make all test

FROM alpine:3.12.7 as production
RUN apk add --no-cache fts libressl libevent libpcap libnet
WORKDIR /root/
COPY --from=builder /opt/sslsplit/sslsplit /usr/local/bin/sslsplit
ENTRYPOINT [ "sslsplit" ]
CMD [ "-V" ]