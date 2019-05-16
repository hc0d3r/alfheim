CFLAGS+=-Wall -Wextra -O3
SRCDIR=src
OBJDIR=lib


OBJS =		$(OBJDIR)/file.o \
		$(OBJDIR)/str.o \
		$(OBJDIR)/mem.o \
		$(OBJDIR)/inject.o \
		$(OBJDIR)/ignotum_ptrace.o \
		$(OBJDIR)/ignotum_mem.o \
		$(OBJDIR)/main.o

ps-inject: $(OBJS)
	$(CC) $(CFLAGS) -o ps-inject $(OBJS)


$(OBJDIR)/%.o: $(SRCDIR)/%.c $(SRCDIR)/%.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) ps-inject
