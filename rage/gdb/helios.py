import gdb


class Helios(gdb.Command):
    def __init__(self):
        super(Helios, self).__init__("helios", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        self.define_leak(arg)  

    def define_leak(self, arg):
        """
        Uses xinfo to determine which segment a pointer is in 
        ex heap, stack, or libc. Then it will find the offset
        from the base of the segment and return the address.
        """

        gdb.execute("xinfo *%s" % arg)     
