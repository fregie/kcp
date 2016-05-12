objects = action.o args.o des.o cJSON.o log.o crypto.o crypto_secretbox_salsa208poly1305.o hash.o decode.o

GTS-server:GTS-client GTS-server.o nat.o $(objects)
	$(CC) -o GTS-server GTS-server.o nat.o $(objects) -lm -lsodium -g
GTS-client:GTS-client.o $(objects)
	$(CC) -o GTS-client GTS-client.o $(objects) -lm -lsodium -g
GTS-server.o:args.h action.h
	$(CC) -c GTS-server.c -g
GTS-client.o:args.h action.h
	$(CC) -c GTS-client.c -g
action.o:args.h
	$(CC) -c action.c -g
args.o:args.h des.h cJSON.h log.h crypto.h b64.h
	$(CC) -c args.c -g
des.o:des.h
	$(CC) -c des.c -g
cJSON.o:cJSON.h
	$(CC) -c cJSON.c -g
log.o:log.h
	$(CC) -c log.c -g
crypto.o:crypto.h crypto_secretbox_salsa208poly1305.h
	$(CC) -c crypto.c -g
crypto_secretbox_salsa208poly1305.o:crypto_secretbox_salsa208poly1305.h
	$(CC) $(CFLAGS) $(LDFLAGS) -c crypto_secretbox_salsa208poly1305.c -g
hash.o:args.h hash.h
	$(CC) -c hash.c -g
nat.o:nat.h hash.h
	$(CC) -c nat.c -g
decode.o:b64.h
	$(CC) -c decode.c -g
clean:
	rm GTS-client GTS-server GTS-client.o GTS-server.o nat.o $(objects)
install:
	mkdir /usr/bin
	mkdir /etc/GTS
	cp ./GTS-server /usr/bin/
	cp ./GTS-client /usr/bin/
	cp ../samples/client.json ../samples/client_down.sh ../samples/client_up.sh /etc/GTS/
	cp ../samples/server.json ../samples/server_down.sh ../samples/server_up.sh /etc/GTS/
uninstall:
	rm /usr/bin/GTS-server
	rm /usr/bin/GTS-client
	rm -r /etc/GTS/