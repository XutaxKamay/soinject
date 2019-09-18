CC=gcc

# INJECT
INJECT_INCLUDES = includes/
INJECT_SRC = src/inject.c
INJECT_CFLAGS = -g -Wall -I$(INJECT_INCLUDES) 
INJECT32_DEBUG = inject32.dbg
INJECT64_DEBUG = inject64.dbg

.PHONY: all clean

all: $(INJECT64_DEBUG) $(INJECT32_DEBUG) 

$(INJECT32_DEBUG): $(INJECT_SRC)
	$(CC) $(INJECT_CFLAGS) -m32 -o $@ $(INJECT_SRC) -ldl

$(INJECT64_DEBUG): $(INJECT_SRC)
	$(CC) $(INJECT_CFLAGS) -m64 -o $@ $(INJECT_SRC) -ldl

clean:
	${RM} ${INJECT32_DEBUG} ${INJECT64_DEBUG} 
