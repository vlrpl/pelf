
"""
An ELF header resides at the beginning and holds a ``road map'' describing the file's organization. 
Sections hold the bulk of object file information for the linking view: 
instructions, data, symbol table, relocation information, and so on. 

A program header table tells the system how to create a process image. 
Files used to build a process image (execute a program) must have a program header table; 
relocatable files do not need one. 
A section header table contains information describing the file's sections. 
Every section has an entry in the table; each entry gives information such as the section name, the section size, and so on. 
Files used during linking must have a section header table; other object files may or may not have one.

Object File Format

Linking View
ELF Header
Program header table
optional
Section 1
...
Section n
...
Section header table
required


Execution View
ELF Header
Program header table
required
Segment 1
Segment 2
Segment 3
...
Section header table
optional

32-Bit Data Types
Name	Size	Alignment	Purpose
Elf32_Addr	4	4	Unsigned program address
Elf32_Off	4	4	Unsigned file offset
Elf32_Half	2	2	Unsigned medium integer
Elf32_Word	4	4	Unsigned integer
Elf32_Sword	4	4	Signed integer
unsigned char	1	1	Unsigned small integer
64-Bit Data Types

Name	Size	Alignment	Purpose
Elf64_Addr	8	8	Unsigned program address
Elf64_Off	8	8	Unsigned file offset
Elf64_Half	2	2	Unsigned medium integer
Elf64_Word	4	4	Unsigned integer
Elf64_Sword	4	4	Signed integer
Elf64_Xword	8	8	Unsigned long integer
Elf64_Sxword	8	8	Signed long integer
unsigned char	1	1	Unsigned small integer
"""

"""
ELF Header (http://refspecs.linuxfoundation.org/elf/gabi4+/ch4.eheader.html)
#define EI_NIDENT 16

typedef struct {
        unsigned char   e_ident[EI_NIDENT];
        Elf32_Half      e_type;
        Elf32_Half      e_machine;
        Elf32_Word      e_version;
        Elf32_Addr      e_entry;
        Elf32_Off       e_phoff;
        Elf32_Off       e_shoff;
        Elf32_Word      e_flags;
        Elf32_Half      e_ehsize;
        Elf32_Half      e_phentsize;
        Elf32_Half      e_phnum;
        Elf32_Half      e_shentsize;
        Elf32_Half      e_shnum;
        Elf32_Half      e_shstrndx;
} Elf32_Ehdr;

typedef struct {
        unsigned char   e_ident[EI_NIDENT];
        Elf64_Half      e_type;
        Elf64_Half      e_machine;
        Elf64_Word      e_version;
        Elf64_Addr      e_entry;
        Elf64_Off       e_phoff;
        Elf64_Off       e_shoff;
        Elf64_Word      e_flags;
        Elf64_Half      e_ehsize;
        Elf64_Half      e_phentsize;
        Elf64_Half      e_phnum;
        Elf64_Half      e_shentsize;
        Elf64_Half      e_shnum;
        Elf64_Half      e_shstrndx;
} Elf64_Ehdr;
"""

"""
Section header 

typedef struct {
	Elf32_Word	sh_name;
	Elf32_Word	sh_type;
	Elf32_Word	sh_flags;
	Elf32_Addr	sh_addr;
	Elf32_Off	sh_offset;
	Elf32_Word	sh_size;
	Elf32_Word	sh_link;
	Elf32_Word	sh_info;
	Elf32_Word	sh_addralign;
	Elf32_Word	sh_entsize;
} Elf32_Shdr;

typedef struct {
	Elf64_Word	sh_name;
	Elf64_Word	sh_type;
	Elf64_Xword	sh_flags;
	Elf64_Addr	sh_addr;
	Elf64_Off	sh_offset;
	Elf64_Xword	sh_size;
	Elf64_Word	sh_link;
	Elf64_Word	sh_info;
	Elf64_Xword	sh_addralign;
	Elf64_Xword	sh_entsize;
} Elf64_Shdr;

"""

import sys
import struct 

class FileWrap:
    def __init__(self, file_name="test.elf"):
        try:
            self.fd = open(file_name)
        except IOError as e:
            print "I/O error({0}): {1}".format(e.errno, e.strerror)
            sys.exit(1)

    def look_ahead(self, length, pos = None): 
        if pos is None:
            pos = self.fd.tell()

        buff = self.fd.read(length)
        self.fd.seek(pos)

        return buff

    def read_bytes_at_offset(self, num_bytes, offset):
        self.fd.seek(offset)
        self.read_bytes(num_bytes)

    def read_bytes(self, num_bytes):
        try:
            return self.fd.read(num_bytes)
        except IOError as e:
            print "I/O error({0}): {1}".format(e.errno, e.strerror)

    def look_ahead_at_offset(self, offset, length):
        origin_pos = self.fd.tell()
        self.fd.seek(offset)

        return self.look_ahead(length, origin_pos)

    def close_file(self):
        self.fd.close()


class Elf(FileWrap):
    """
    Need to check the magic elf header EI_MAG0-EI_MAG3 
    """
    def is_valid(self):
        e_ident = self.look_ahead(4)
        
        if e_ident == chr(0x7f) + "ELF":
            return True
        
        return False


    def parse_header(self):

       ehdr_fields = ['e_ident', 'e_type', 'e_machine',
                      'e_version', 'e_entry', 'e_phoff',
                      'e_shoff', 'e_flags', 'e_ehsize',
                      'e_phentsize', 'e_phnum', 'e_shentsize',
                      'e_shnum', 'e_shstrndx']
       
       fmt = '16s'

       arch_class = self.get_arch()

       if arch_class == 1:
           fmt += '2H5I6H'
       elif arch_class == 2:
           fmt += '2HI3QI6H'
       else:
           print "ELFCLASSNONE"
           sys.exit(0)
           
       header_bytes = self.read_bytes(struct.calcsize(fmt))
       self.ehdr = dict(zip(ehdr_fields, struct.unpack(fmt, header_bytes)))

       """ 
       ET_NONE	        0       No file type
       ET_REL	        1       Relocatable file
       ET_EXEC	        2       Executable file
       ET_DYN	        3       Shared object file
       ET_CORE	        4       Core file
       ET_LOOS	        0xfe00  Operating system-specific
       ET_HIOS	        0xfeff  Operating system-specific
       ET_LOPROC	0xff00  Processor-specific
       ET_HIPROC	0xffff  Processor-specific
       
       messages took roughly from:
       http://sourceforge.net/apps/trac/elftoolchain/browser/trunk/readelf/readelf.c
       
       instead of switches here as you can see there is an extensive use of dictionary
       it could be implemented in a much more flexible way but it is a simple bytes parser 
       which probably will stay as is for a long long time
       """
    def print_header(self):
        h_id = self.ehdr['e_ident']
        #e_type_attrs   = 
        print "ELF Header:"
        print "  Magic:  ", 
        print "".join("%02x " % ord(c) for c in h_id)

        print "  Class:\t\t\t\t{0}".format({0: 'ELFNONE', 
                                            1: 'ELF32', 
                                            2: 'ELF64'}[ord(h_id[4])])

        print "  Data:\t\t\t\t\t{0}".format({0: "Invalid data encoding", 
                                             1: "2's complement, little endian", 
                                             2: "2's complement, big endian"}[ord(h_id[5])])

        print "  Version:\t\t\t\t{0}".format({0: "0 (invalid)", 
                                              1: "1 (current)"}[ord(h_id[6])])

        print "  OS/ABI:\t\t\t\t{0}".format({0: "UNIX - System V", 
                                             1: "Unix - HPUX", 
                                             2: "UNIX - Netbsd", 
                                             3: "UNIX - Linux"}[ord(h_id[7])])

        print "  ABI Version:\t\t\t\t{0}".format(ord(h_id[8]))
        print "  Type:\t\t\t\t\t{0}".format({0: "NONE", 
                                             1: "REL (Relocatable file)", 
                                             2: "EXEC (Executable file)", 
                                             3: "DYN (Shared object file)",  
                                             4: "CORE (Core file)", 
                                             0xfe00: "LOOS (Operating system-specific)", 
                                             0xfeff: "ET_HIOS (Operating system-specific)",
                                             0xff00: "LOPROC (Processor-specific)", 
                                             0xffff: "HIPROC (Processor-specific)"}[self.ehdr['e_type']])

        # don't want all the architectures
        print "  Machine:\t\t\t\t{0}".format({0:  "No Machine", 
                                              2:  "SPARC", 
                                              3:  "Intel 80386",
                                              50: "Intel IA-64 processor architecture",
                                              62: "AMD x86-64 architecture"}[self.ehdr['e_machine']]) 

        print "  Version:\t\t\t\t{0}".format({0: "Invalid version", 
                                      1: "Current version"}[self.ehdr['e_version']])
 
        print "  Entry point address:\t\t\t0x{0:x}".format(self.ehdr['e_entry'])
        print "  Start of program headers:\t\t{0} (bytes into file)".format(self.ehdr['e_phoff'])
        print "  Start of section headers:\t\t{0} (bytes into file)".format(self.ehdr['e_shoff'])
        print "  Flags:\t\t\t\t0x{0}".format(self.ehdr['e_flags'])
        print "  Size of this header:\t\t\t{0} (bytes)".format(self.ehdr['e_ehsize'])
        print "  Size of program headers:\t\t{0} (bytes)".format(self.ehdr['e_phentsize'])
        print "  Number of program headers:\t\t{0}".format(self.ehdr['e_phnum'])
        print "  Size of section headers:\t\t{0} (bytes)".format(self.ehdr['e_shentsize'])
        print "  Number of section headers:\t\t{0}".format(self.ehdr['e_shnum'])
        print "  Section header string table index:\t{0}".format(self.ehdr['e_shstrndx'])
        
        #print self.ehdr
        

    def get_arch(self):
        return ord(self.look_ahead_at_offset(4,1)) 

if __name__ == '__main__':

    # no args check crap
    fname = sys.argv[1]

    elf = Elf(fname)
    
    if elf.is_valid() == False:
        print "File {0} is not a valid elf".format(fname)

    
    ### Print header informations ###
    # print "File {0} is a valid elf".format(fname)

    elf.parse_header()
    elf.print_header()
    
    




