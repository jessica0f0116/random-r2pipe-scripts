#get apisetschema default mapping from apisetschema.dll... hacky
#example output https://gist.github.com/jessica0f0116/b9fe66bf584e2e47a5133a8b7d8f38c2
import r2pipe
import sys
import subprocess

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
                #nice c snippet to resolve api set
                #https://gist.github.com/lucasg/9aa464b95b4b7344cb0cddbdb4214b25
                result = subprocess.run(['apisetlookup.exe', hostname], stdout=subprocess.PIPE)
                hostname = result.stdout.decode('ascii')
                if hostname[1] != "x":
                    hostname = hostname.strip('\r\n').split('>')
                    if len(hostname) > 1:
                        hostname = hostname[1][1:]
                    else:
                        hostname = hostname[0]
                else:
                    hostname = ""
            hostname = hostname.rstrip()
        hosts.append(hostname)
        numhosts -= 1
    s = '{{ \"apiset name\": \"{}\", \"hosts\": \"{}\" }},\n'.format(
        apiname, hostname)
    return s

def get_apiset_schema(apisetaddr, nsoffs, numentries):
    file = open('apiset_base_schema.json', 'w')
    firstline = '{ \"apiset entries\": [\n'
    file.write(firstline)
    while numentries > 0:
        numentries -= 1
        schentry = get_namespace_entries(apisetaddr, nsoffs)
        if numentries == 1:
            schentry = schentry.rsplit(',', 1)[0] + '\n'
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
