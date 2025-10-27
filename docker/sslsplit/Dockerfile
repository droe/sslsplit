FROM alpine:latest as builder
RUN apk add --no-cache fts libevent libpcap libnet
RUN apk add --no-cache libc-dev fts-dev libevent-dev libpcap-dev libnet-dev \
                       openssl openssl-dev check-dev linux-headers gcc make git
COPY . /opt/sslsplit
WORKDIR /opt/sslsplit
ENV LIBS -lfts
ENV TCPPFLAGS -DDOCKER
RUN export SOURCE_DATE_EPOCH=$(stat -c '%Y' *.c *.h|sort -r|head -1); \
    make clean && make all test

FROM alpine:latest as production
RUN apk add --no-cache fts libevent libpcap libnet
WORKDIR /root/
COPY --from=builder /opt/sslsplit/sslsplit /usr/local/bin/sslsplit
#EXPOSE 80 443
ENTRYPOINT [ "sslsplit" ]
CMD [ "-V" ]

