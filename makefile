objects = action.o args.o des.o cJSON.o

GTS-server:GTS-client GTS-server.o $(objects)
	cc -o GTS-server GTS-server.o $(objects) -lm -g
GTS-client:GTS-client.o $(objects)
	cc -o GTS-client GTS-client.o $(objects) -lm -g
GTS-server.o:args.h action.h
	cc -c GTS-server.c -g
GTS-client.o:args.h action.h
	cc -c GTS-client.c -g
action.o:args.h
	cc -c action.c -g
args.o:args.h des.h cJSON.h
	cc -c args.c -g
des.o:des.h
	cc -c des.c -g
cJSON.o:cJSON.h
	cc -c cJSON.c

	
clean:
	rm GTS-client GTS-server GTS-client.o GTS-server.o $(objects)