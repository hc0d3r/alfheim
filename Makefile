CFLAGS+=-Wall -Wextra -O3
SRCDIR=src
OBJDIR=lib


FILES =	file.o str.o mem.o inject.o \
	ignotum_ptrace.o ignotum_mem.o ptrace.o \
	remote_write.o main.o

OBJS = $(addprefix $(OBJDIR)/, $(FILES))

alfheim: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^


$(OBJDIR)/%.o: $(SRCDIR)/%.c $(SRCDIR)/%.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) ps-inject
