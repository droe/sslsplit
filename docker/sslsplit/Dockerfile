FROM alpine:3.8 as builder
RUN apk add --no-cache fts libressl libevent libpcap libnet
RUN apk add --no-cache libressl-dev libevent-dev libpcap-dev libnet-dev \
                       check-dev libc-dev fts-dev linux-headers gcc make git
COPY . /opt/sslsplit
WORKDIR /opt/sslsplit
ENV LIBS -lfts
ENV TCPPFLAGS -DDOCKER
RUN export SOURCE_DATE_EPOCH=$(stat -c '%Y' *.c *.h|sort -r|head -1); \
    make clean && make all test

FROM alpine:3.8 as production
RUN apk add --no-cache fts libressl libevent libpcap libnet
WORKDIR /root/
COPY --from=builder /opt/sslsplit/sslsplit /usr/local/bin/sslsplit
#EXPOSE 80 443
ENTRYPOINT [ "sslsplit" ]
CMD [ "-V" ]

