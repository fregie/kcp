objects = action.o args.o des.o cJSON.o log.o crypto.o crypto_secretbox_salsa208poly1305.o hash.o decode.o

GTS-server:GTS-client GTS-server.o nat.o $(objects)
	$(CC) -o GTS-server GTS-server.o nat.o $(objects) -lm -lsodium -pg
GTS-client:GTS-client.o $(objects)
	$(CC) -o GTS-client GTS-client.o $(objects) -lm -lsodium -pg
GTS-server.o:args.h action.h
	$(CC) -c GTS-server.c -pg
GTS-client.o:args.h action.h
	$(CC) -c GTS-client.c -pg
action.o:args.h
	$(CC) -c action.c -pg
args.o:args.h des.h cJSON.h log.h crypto.h b64.h
	$(CC) -c args.c -pg
des.o:des.h
	$(CC) -c des.c -pg
cJSON.o:cJSON.h
	$(CC) -c cJSON.c -pg
log.o:log.h
	$(CC) -c log.c -pg
crypto.o:crypto.h crypto_secretbox_salsa208poly1305.h
	$(CC) -c crypto.c -pg
crypto_secretbox_salsa208poly1305.o:crypto_secretbox_salsa208poly1305.h
	$(CC) -c crypto_secretbox_salsa208poly1305.c -pg
hash.o:args.h hash.h
	$(CC) -c hash.c -pg
nat.o:nat.h hash.h
	$(CC) -c nat.c -pg
decode.o:b64.h
	$(CC) -c decode.c -pg
clean:
	rm GTS-client GTS-server GTS-client.o GTS-server.o nat.o $(objects)
install:
	install -d /etc/GTS
	install -D ./GTS-server /usr/bin/
	install -D ./GTS-client /usr/bin/
	install -D ../samples/* /etc/GTS/
uninstall:
	rm /usr/bin/GTS-server
	rm /usr/bin/GTS-client
	rm -rf /etc/GTS/