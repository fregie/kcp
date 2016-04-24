objects = action.o args.o des.o cJSON.o log.o crypto.o crypto_secretbox_salsa208poly1305.o

GTS-server:GTS-client GTS-server.o $(objects)
	cc -o GTS-server GTS-server.o $(objects) -lm -lsodium -g
GTS-client:GTS-client.o $(objects)
	cc -o GTS-client GTS-client.o $(objects) -lm -lsodium -g
GTS-server.o:args.h action.h
	cc -c GTS-server.c -g
GTS-client.o:args.h action.h
	cc -c GTS-client.c -g
action.o:args.h
	cc -c action.c -g
args.o:args.h des.h cJSON.h log.h crypto.h
	cc -c args.c -g
des.o:des.h
	cc -c des.c -g
cJSON.o:cJSON.h
	cc -c cJSON.c -g
log.o:log.h
	cc -c log.c -g
crypto.o:crypto.h
	cc -c crypto.c -g
crypto_secretbox_salsa208poly1305.o:crypto_secretbox_salsa208poly1305.h
	cc -c crypto_secretbox_salsa208poly1305.c -g
	
clean:
	rm GTS-client GTS-server GTS-client.o GTS-server.o $(objects)