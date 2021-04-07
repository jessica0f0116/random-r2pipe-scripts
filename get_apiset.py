#get apisetschema default mapping from apisetschema.dll
import r2pipe
import sys

r2 = r2pipe.open()

def get_apiset_section_addr():
    sections = r2.cmdj('iSj')
    vaddr = 0
    for s in sections:
        if s['name'] == ".apiset":
            vaddr = s['vaddr']
    if vaddr == 0:
        print(".apiset section not present")
        sys.exit(1)
    return vaddr

def get_namespace_header(vaddr):
    r2.cmd('s 0x{:x}'.format(vaddr))
    descriptions = [
        'schema extension', 'map size', 'is sealed',
        'number of apisets', 'namespace entries offset',
        'hash entries offset', 'hash multiplier'
        ]
    fields = r2.cmdj('pxwj 28')
    zipobj = zip(descriptions, fields)
    nsheader = dict(zipobj)
    return nsheader

def get_namespace_entries(apisetaddr, nsoffs):
    namespace_entry_addr = apisetaddr + nsoffs
    fields = r2.cmdj('pxwj 24 @ 0x{:x}'.format(namespace_entry_addr))
    nameaddr = apisetaddr + fields[1]
    namesz = fields[2]
    padding = 18
    hostsoffs = fields[4] + padding
    hostaddr = apisetaddr + hostsoffs
    numhosts = fields[5]
    apiname = r2.cmd('psW 0x{:x} @ 0x{:x}'.format(namesz, nameaddr))
    apiname = apiname.rstrip()
    hosts = []
    hoststr = r2.cmd('psW @ 0x{:x}'.format(hostaddr))
    while numhosts > 0:
        hostname = hoststr.split('.dll')
        if len(hostname) >= numhosts:
            if len(hostname) >= 2:
                hostname = hostname[numhosts - 1] + ".dll"
            else:
                hostname = hostname[numhosts - 1]
            hostname = hostname.rstrip()
        hosts.append(hostname)
        numhosts -= 1
    s = '{{ \"apiset name\": \"{}\", \"hosts\": \"{}\" }},\r\n'.format(
        apiname, hostname)
    return s

def get_apiset_schema(apisetaddr, nsoffs, numentries):
    file = open('apiset_base_schema.json', 'w')
    firstline = '{ \"apiset entries\": [\r\n'
    file.write(firstline)
    while numentries > 1:
        numentries -= 1
        schentry = get_namespace_entries(apisetaddr, nsoffs)
        if numentries == 1:
            schentry = schentry.rsplit(',', 1)[0] + '\r\n'
        #print(schentry)
        file.write(schentry)
        nsoffs += 24
    file.write('] }')
    file.close()

def main():
    apisetaddr = get_apiset_section_addr()
    print('.apiset section address: {:x}'.format(apisetaddr))
    nsheader = get_namespace_header(apisetaddr)
    print('Namespace header entries: {}'.format(nsheader))
    nsoffs = nsheader['namespace entries offset']
    numentries = nsheader['number of apisets']
    get_apiset_schema(apisetaddr, nsoffs, numentries)

main()