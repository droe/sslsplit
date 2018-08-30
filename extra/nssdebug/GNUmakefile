all: snoop-nss-verify.so

snoop-nss-verify.so: snoop-nss-verify.c
	$(CC) -shared -fPIC -o $@ $< -ldl

clean:
	rm -f snoop-nss-verify.so
