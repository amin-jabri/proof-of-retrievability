
#-finstrument-functions -lSaturn -pg 

all: por-misc.o por.h por-keys.o por-file.o por-app.c
	gcc -g -Wall -O3 -lcrypto -o por por-app.c por-misc.o por-keys.o por-file.o

por-s3: por-misc.o por.h por-keys.o por-file.o por-s3.o por-app.c ../libs3-1.4/build/lib/libs3.a ../libs3-1.4/build/include/libs3.h
	gcc -DUSE_S3 -g -Wall -O3 -lcurl -lcrypto -lxml2 -lz -o por-s3 por-app.c por-misc.o por-keys.o por-file.o por-s3.o ../libs3-1.4/build/lib/libs3.a 

por-keys.o: por-keys.c por.h
	gcc -g -Wall -O3 $(MAKEARGS) -c por-keys.c

por-misc.o: por-misc.c por.h
	gcc -g -Wall -O3 $(MAKEARGS) -c por-misc.c

por-file.o: por-file.c por.h
	gcc -g -Wall -O3 $(MAKEARGS) -c por-file.c

por-s3.o: por-s3.c por.h
	gcc -DUSE_S3 -g -Wall -O3 -I../libs3-1.4/build/include/ -c por-s3.c

porlib: por-core.o por-misc.o por-keys.o por-file.o
	ar -rv porlib.a por-misc.o por-keys.o por-file.o

clean:
	rm -rf *.o por.dSYM por por-s3 *.tag