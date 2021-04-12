import r2pipe
import sys

r2 = r2pipe.open()
file = open('win32u_syscalls.json', 'w')

r2.cmd('aaa')
num_syscalls = r2.cmd('aflc')
firstline = '{{\"number of syscalls\":{}, \"syscall entries\":[\r\n'.format(
    num_syscalls.rstrip())
file.write(firstline)
addrs = r2.cmdj('aflqj')
for addr in addrs:
    hexaddr = hex(addr)
    syscallnum = r2.cmd("p8 1 @ {}+5".format(hexaddr)).replace('\n', '')
    syscallnum += r2.cmd("p8 1 @ {}+4".format(hexaddr)).replace('\n', '')
    syscallname = r2.cmdj("afij @ {}".format(hexaddr))[0]['name'][15:]
    if syscallnum == 'cccc':
        continue
    jsonline = '{{\"syscall name":\"{}\", \"syscall number\":\"0x{}\"}},\r\n'.format(
        syscallname, syscallnum)
    file.write(jsonline)
file.write(']}')
file.close()
