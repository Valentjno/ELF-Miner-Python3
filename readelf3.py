import argparse
import os
import sys
import string

sys.path.insert(0, '.')
from elftools import __version__
from elftools.common.exceptions import ELFError
from elftools.common.py3compat import (
        ifilter, byte2int, bytes2str, itervalues, str2bytes, iterbytes)
from elftools.elf.elffile import ELFFile
from elftools.elf.dynamic import DynamicSection, DynamicSegment
from elftools.elf.enums import ENUM_D_TAG
from elftools.elf.segments import InterpSegment
from elftools.elf.sections import NoteSection, SymbolTableSection
from elftools.elf.gnuversions import (
    GNUVerSymSection, GNUVerDefSection,
    GNUVerNeedSection,
    )
from elftools.elf.relocation import RelocationSection
from elftools.elf.descriptions import (
    describe_ei_class, describe_ei_data, describe_ei_version,
    describe_ei_osabi, describe_e_type, describe_e_machine,
    describe_e_version_numeric, describe_p_type, describe_p_flags,
    describe_sh_type, describe_sh_flags,
    describe_symbol_type, describe_symbol_bind, describe_symbol_visibility,
    describe_symbol_shndx, describe_reloc_type, describe_dyn_tag,
    describe_dt_flags, describe_dt_flags_1, describe_ver_flags, describe_note,
    describe_attr_tag_arm
    )

from elftools.elf.constants import E_FLAGS
from elftools.elf.constants import E_FLAGS_MASKS
from elftools.dwarf.dwarfinfo import DWARFInfo
from elftools.dwarf.descriptions import (
    describe_reg_name, describe_attr_value, set_global_machine_arch,
    describe_CFI_instructions, describe_CFI_register_rule,
    describe_CFI_CFA_rule,
    )
from elftools.dwarf.constants import (
    DW_LNS_copy, DW_LNS_set_file, DW_LNE_define_file)
from elftools.dwarf.callframe import CIE, FDE, ZERO


class ReadElf(object):
    """ display_* methods are used to emit output into the output stream """

    def __init__(self, file, output):
        """ file:
                stream object with the ELF file to read

            output:
                output stream to write to
        """
        self.elffile = ELFFile(file)
        self.output = output

        # Lazily initialized if a debug dump is requested
        self._dwarfinfo = None

        self._versioninfo = None

    def display_file_header(self):
        """ Display the ELF file header """
        self._emitline('ELF Header:')
        self._emit('  Magic:   ')
        self._emit(' '.join(f'{byte2int(b):02x}' for b in self.elffile.e_ident_raw))
        
        self._emitline('      ')
        header = self.elffile.header
        e_ident = header['e_ident']

        identification = ' '.join(f'{byte2int(b):02x}' for b in self.elffile.e_ident_raw)
        file_class = describe_ei_class(e_ident['EI_CLASS'])
        data = describe_ei_data(e_ident['EI_DATA'])
        version = describe_ei_version(e_ident['EI_VERSION'])
        abi = describe_ei_osabi(e_ident['EI_OSABI'])
        abi_version = e_ident['EI_ABIVERSION']
        type_file = describe_e_type(header['e_type'])
        machine = describe_e_machine(header['e_machine'])
        version = describe_e_version_numeric(header['e_version'])
        entry_point_address = self._format_hex(header['e_entry'])
        start_program_headers = header['e_phoff']
        start_section_headers = header['e_shoff']
        flags = self._format_hex(header['e_flags']) + self.decode_flags(header['e_flags'])
        header_size = header['e_ehsize']
        size_program_header = header['e_phentsize']
        num_program_header = header['e_phnum']
        size_section_header = header['e_shentsize']
        num_section_header = header['e_shnum']
        str_table_ind = header['e_shstrndx']

        return (identification, file_class, data, version, abi, abi_version, type_file,
                machine, version, entry_point_address, start_program_headers,
                start_section_headers, flags, header_size, size_program_header,
                num_program_header, size_section_header, num_section_header, str_table_ind)

    def decode_flags(self, flags):
        description = ""
        if self.elffile['e_machine'] == "EM_ARM":
            eabi = flags & E_FLAGS.EF_ARM_EABIMASK
            flags &= ~E_FLAGS.EF_ARM_EABIMASK

            if flags & E_FLAGS.EF_ARM_RELEXEC:
                description += ', relocatable executable'
                flags &= ~E_FLAGS.EF_ARM_RELEXEC

            if eabi == E_FLAGS.EF_ARM_EABI_VER5:
                EF_ARM_KNOWN_FLAGS = E_FLAGS.EF_ARM_ABI_FLOAT_SOFT | E_FLAGS.EF_ARM_ABI_FLOAT_HARD | E_FLAGS.EF_ARM_LE8 | E_FLAGS.EF_ARM_BE8
                description += ', Version5 EABI'
                if flags & E_FLAGS.EF_ARM_ABI_FLOAT_SOFT:
                    description += ", soft-float ABI"
                elif flags & E_FLAGS.EF_ARM_ABI_FLOAT_HARD:
                    description += ", hard-float ABI"

                if flags & E_FLAGS.EF_ARM_BE8:
                    description += ", BE8"
                elif flags & E_FLAGS.EF_ARM_LE8:
                    description += ", LE8"

                if flags & ~EF_ARM_KNOWN_FLAGS:
                    description += ', <unknown>'
            else:
                description += ', <unrecognized EABI>'

        elif self.elffile['e_machine'] == "EM_MIPS":
            if flags & E_FLAGS.EF_MIPS_NOREORDER:
                description += ", noreorder"
            if flags & E_FLAGS.EF_MIPS_PIC:
                description += ", pic"
            if flags & E_FLAGS.EF_MIPS_CPIC:
                description += ", cpic"
            if flags & E_FLAGS.EF_MIPS_ABI2:
                description += ", abi2"
            if flags & E_FLAGS.EF_MIPS_32BITMODE:
                description += ", 32bitmode"
            if flags & E_FLAGS_MASKS.EFM_MIPS_ABI_O32:
                description += ", o32"
            elif flags & E_FLAGS_MASKS.EFM_MIPS_ABI_O64:
                description += ", o64"
            elif flags & E_FLAGS_MASKS.EFM_MIPS_ABI_EABI32:
                description += ", eabi32"
            elif flags & E_FLAGS_MASKS.EFM_MIPS_ABI_EABI64:
                description += ", eabi64"
            if (flags & E_FLAGS.EF_MIPS_ARCH) == E_FLAGS.EF_MIPS_ARCH_1:
                description += ", mips1"
            if (flags & E_FLAGS.EF_MIPS_ARCH) == E_FLAGS.EF_MIPS_ARCH_2:
                description += ", mips2"
            if (flags & E_FLAGS.EF_MIPS_ARCH) == E_FLAGS.EF_MIPS_ARCH_3:
                description += ", mips3"
            if (flags & E_FLAGS.EF_MIPS_ARCH) == E_FLAGS.EF_MIPS_ARCH_4:
                description += ", mips4"
            if (flags & E_FLAGS.EF_MIPS_ARCH) == E_FLAGS.EF_MIPS_ARCH_5:
                description += ", mips5"
            if (flags & E_FLAGS.EF_MIPS_ARCH) == E_FLAGS.EF_MIPS_ARCH_32R2:
                description += ", mips32r2"
            if (flags & E_FLAGS.EF_MIPS_ARCH) == E_FLAGS.EF_MIPS_ARCH_64R2:
                description += ", mips64r2"
            if (flags & E_FLAGS.EF_MIPS_ARCH) == E_FLAGS.EF_MIPS_ARCH_32:
                description += ", mips32"
            if (flags & E_FLAGS.EF_MIPS_ARCH) == E_FLAGS.EF_MIPS_ARCH_64:
                description += ", mips64"

        return description


    def _emitline(self, s=""):
        self.output.write(s + '\n')

    def _emit(self, s):
        self.output.write(s)

    def _format_hex(self, addr, fieldsize=None, lead0x=True, fullhex=False):
        s = hex(addr)[2:] if not lead0x else hex(addr)
        if fullhex and len(s) < 18:
            s = '0x' + '0' * (18 - len(s)) + s[2:]
        elif fieldsize and len(s) < fieldsize:
            s = '0x' + '0' * (fieldsize - len(s)) + s[2:]
        return s

    def display_program_headers(self, show_heading=True):
        self._emitline()
        if self.elffile.num_segments() == 0:
            self._emitline('There are no program headers in this file.')
            return

        elfheader = self.elffile.header
        if show_heading:
            self._emitline(f'Elf file type is {describe_e_type(elfheader["e_type"])}')
            self._emitline(f'Entry point is {self._format_hex(elfheader["e_entry"])}')
            self._emitline(f'There are {elfheader["e_phnum"]} program headers, starting at offset {elfheader["e_phoff"]}')
            self._emitline()

        self._emitline('Program Headers:')
        if self.elffile.elfclass == 32:
            self._emitline('  Type           Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg Align')
        else:
            self._emitline('  Type           Offset             VirtAddr           PhysAddr')
            self._emitline('                 FileSiz            MemSiz              Flags  Align')

        for segment in self.elffile.iter_segments():
            self._emit(f'  {describe_p_type(segment["p_type"]):<14} ')

            if self.elffile.elfclass == 32:
                self._emitline(f'{self._format_hex(segment["p_offset"], fieldsize=6)} '
                               f'{self._format_hex(segment["p_vaddr"], fullhex=True)} '
                               f'{self._format_hex(segment["p_paddr"], fullhex=True)} '
                               f'{self._format_hex(segment["p_filesz"], fieldsize=5)} '
                               f'{self._format_hex(segment["p_memsz"], fieldsize=5)} '
                               f'{describe_p_flags(segment["p_flags"]):<3} '
                               f'{self._format_hex(segment["p_align"])}')
            else:
                self._emitline(f'{self._format_hex(segment["p_offset"], fullhex=True)} '
                               f'{self._format_hex(segment["p_vaddr"], fullhex=True)} '
                               f'{self._format_hex(segment["p_paddr"], fullhex=True)}')
                self._emitline(f'                 {self._format_hex(segment["p_filesz"], fullhex=True)} '
                               f'{self._format_hex(segment["p_memsz"], fullhex=True)}  '
                               f'{describe_p_flags(segment["p_flags"]):<3}    '
                               f'{self._format_hex(segment["p_align"], lead0x=False)}')

            if isinstance(segment, InterpSegment):
                self._emitline(f'      [Requesting program interpreter: {segment.get_interp_name()}]')

        if self.elffile.num_sections() == 0:
            return

        self._emitline('\n Section to Segment mapping:')
        self._emitline('  Segment Sections...')

        for nseg, segment in enumerate(self.elffile.iter_segments()):
            self._emit(f'   {nseg:2}     ')

            for section in self.elffile.iter_sections():
                if not section.is_null() and segment.section_in_segment(section):
                    self._emit(f'{section.name} ')

            self._emitline('')

    def display_section_headers(self, show_heading=True):
        """ Display the ELF section headers """
        elfheader = self.elffile.header
        if show_heading:
            self._emitline(f'There are {elfheader["e_shnum"]} section headers, starting at offset {self._format_hex(elfheader["e_shoff"])}')

        if self.elffile.num_sections() == 0:
            self._emitline('There are no sections in this file.')
            return

        self._emitline(f'\nSection Header{"s" if elfheader["e_shnum"] > 1 else ""}:')

        if self.elffile.elfclass == 32:
            self._emitline('  [Nr] Name              Type            Addr     Off    Size   ES Flg Lk Inf Al')
        else:
            self._emitline('  [Nr] Name              Type             Address           Offset')
            self._emitline('       Size              EntSize          Flags  Link  Info  Align')

        sections_data_list = []

        for nsec, section in enumerate(self.elffile.iter_sections()):
            indi_list = []
            self._emit(f'  [{nsec:2}] {section.name:<17.17} {describe_sh_type(section["sh_type"]):<15.15} ')

            indi_list.extend([section.name, describe_sh_type(section["sh_type"])])

            if self.elffile.elfclass == 32:
                self._emitline(f'{self._format_hex(section["sh_addr"], fieldsize=8, lead0x=False)} '
                               f'{self._format_hex(section["sh_offset"], fieldsize=6, lead0x=False)} '
                               f'{self._format_hex(section["sh_size"], fieldsize=6, lead0x=False)} '
                               f'{self._format_hex(section["sh_entsize"], fieldsize=2, lead0x=False)} '
                               f'{describe_sh_flags(section["sh_flags"])} {section["sh_link"]} {section["sh_info"]} {section["sh_addralign"]}')
                indi_list.extend([describe_sh_flags(section["sh_flags"]), self._format_hex(section["sh_size"], fieldsize=6, lead0x=False), self._format_hex(section["sh_entsize"], fieldsize=2, lead0x=False), section["sh_link"], section["sh_info"], section["sh_addralign"]])
            else:
                self._emitline(f' {self._format_hex(section["sh_addr"], fullhex=True, lead0x=False)}  '
                               f'{self._format_hex(section["sh_offset"], fieldsize=16 if section["sh_offset"] > 0xffffffff else 8, lead0x=False)}')
                self._emitline(f'       {self._format_hex(section["sh_size"], fullhex=True, lead0x=False)}  '
                               f'{self._format_hex(section["sh_entsize"], fullhex=True, lead0x=False)} '
                               f'{describe_sh_flags(section["sh_flags"])} {section["sh_link"]} {section["sh_info"]} {section["sh_addralign"]}')
                indi_list.extend([describe_sh_flags(section["sh_flags"]), self._format_hex(section["sh_size"], fullhex=True, lead0x=False), self._format_hex(section["sh_entsize"], fullhex=True, lead0x=False), section["sh_link"], section["sh_info"], section["sh_addralign"]])

            sections_data_list.append(indi_list)

        self._emitline('Key to Flags:')
        self._emitline('  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),')
        self._emitline('  L (link order), O (extra OS processing required), G (group), T (TLS),')
        self._emitline('  C (compressed), x (unknown), o (OS specific), E (exclude),')
        self._emit('  ')
        if self.elffile['e_machine'] == 'EM_ARM':
            self._emit('y (purecode), ')
        self._emitline('p (processor specific)')

        return sections_data_list, "a"

    def display_symbol_tables(self):
        """ Display the symbol tables contained in the file
        """
        self._init_versioninfo()

        symbol_tables = [s for s in self.elffile.iter_sections() if isinstance(s, SymbolTableSection)]

        if not symbol_tables and self.elffile.num_sections() == 0:
            self._emitline('')
            self._emitline('Dynamic symbol information is not available for displaying symbols.')

        for section in symbol_tables:
            if not isinstance(section, SymbolTableSection):
                continue

            if section['sh_entsize'] == 0:
                self._emitline(f"\nSymbol table '{section.name}' has a sh_entsize of zero!")
                continue

            self._emitline(f"\nSymbol table '{section.name}' contains {section.num_symbols()} entries:")

            if self.elffile.elfclass == 32:
                self._emitline('   Num:    Value  Size Type    Bind   Vis      Ndx Name')
            else: # 64
                self._emitline('   Num:    Value          Size Type    Bind   Vis      Ndx Name')

            for nsym, symbol in enumerate(section.iter_symbols()):
                version_info = ''
                # readelf doesn't display version info for Solaris versioning
                if section['sh_type'] == 'SHT_DYNSYM' and self._versioninfo['type'] == 'GNU':
                    version = self._symbol_version(nsym)
                    if version['name'] != symbol.name and version['index'] not in ('VER_NDX_LOCAL', 'VER_NDX_GLOBAL'):
                        if version['filename']:
                            # external symbol
                            version_info = f"@{version['name']} ({version['index']})"
                        else:
                            # internal symbol
                            if version['hidden']:
                                version_info = f"@{version['name']}"
                            else:
                                version_info = f"@@{version['name']}"

                # symbol names are truncated to 25 chars, similarly to readelf
                self._emitline(f'{nsym:6d}: {self._format_hex(symbol["st_value"], fullhex=True, lead0x=False)} {symbol["st_size"]:5d} '
                            f'{describe_symbol_type(symbol["st_info"]["type"]):<7} '
                            f'{describe_symbol_bind(symbol["st_info"]["bind"]):<6} '
                            f'{describe_symbol_visibility(symbol["st_other"]["visibility"]):<7} '
                            f'{describe_symbol_shndx(symbol["st_shndx"]):4} {symbol.name:.25}{version_info}')

    def display_dynamic_tags(self):
        """ Display the dynamic tags contained in the file
        """
        has_dynamic_sections = False
        for section in self.elffile.iter_sections():
            if not isinstance(section, DynamicSection):
                continue

            has_dynamic_sections = True
            self._emitline(f"\nDynamic section at offset {self._format_hex(section['sh_offset'])} contains {section.num_tags()} entries:")
            self._emitline("  Tag        Type                         Name/Value")

            padding = 20 + (8 if self.elffile.elfclass == 32 else 0)
            for tag in section.iter_tags():
                if tag.entry.d_tag == 'DT_NEEDED':
                    parsed = f'Shared library: [{tag.needed}]'
                elif tag.entry.d_tag == 'DT_RPATH':
                    parsed = f'Library rpath: [{tag.rpath}]'
                elif tag.entry.d_tag == 'DT_RUNPATH':
                    parsed = f'Library runpath: [{tag.runpath}]'
                elif tag.entry.d_tag == 'DT_SONAME':
                    parsed = f'Library soname: [{tag.soname}]'
                elif tag.entry.d_tag.endswith(('SZ', 'ENT')):
                    parsed = f'{tag["d_val"]} (bytes)'
                elif tag.entry.d_tag == 'DT_FLAGS':
                    parsed = describe_dt_flags(tag.entry.d_val)
                elif tag.entry.d_tag == 'DT_FLAGS_1':
                    parsed = f'Flags: {describe_dt_flags_1(tag.entry.d_val)}'
                elif tag.entry.d_tag.endswith(('NUM', 'COUNT')):
                    parsed = f'{tag["d_val"]}'
                elif tag.entry.d_tag == 'DT_PLTREL':
                    s = describe_dyn_tag(tag.entry.d_val)
                    if s.startswith('DT_'):
                        s = s[3:]
                    parsed = f'{s}'
                else:
                    parsed = f'{tag["d_val"]:#x}'

                self._emitline(f" {self._format_hex(ENUM_D_TAG.get(tag.entry.d_tag, tag.entry.d_tag), fullhex=True, lead0x=True)} "
                            f"{padding:<{padding}} ({tag.entry.d_tag[3:]}) {parsed}")
        if not has_dynamic_sections:
            self._emitline("\nThere is no dynamic section in this file.")


    def display_notes(self):
        """ Display the notes contained in the file
        """
        for section in self.elffile.iter_sections():
            if isinstance(section, NoteSection):
                for note in section.iter_notes():
                    self._emitline(f"\nDisplaying notes found in: {section.name}")
                    self._emitline('  Owner                 Data size Description')
                    self._emitline('  {:<20} {:8}  {}'.format(
                        note['n_name'],
                        self._format_hex(note['n_descsz'], fieldsize=8),
                        describe_note(note,"None")))

    def display_relocations(self):
        """ Display the relocations contained in the file
        """
        has_relocation_sections = False
        for section in self.elffile.iter_sections():
            if not isinstance(section, RelocationSection):
                continue

            has_relocation_sections = True
            self._emitline(f"\nRelocation section '{section.name}' at offset {self._format_hex(section['sh_offset'])} contains {section.num_relocations()} entries:")
            if section.is_RELA():
                self._emitline("  Offset          Info           Type           Sym. Value    Sym. Name + Addend")
            else:
                self._emitline(" Offset     Info    Type            Sym.Value  Sym. Name")

            symtable = self.elffile.get_section(section['sh_link'])

            for rel in section.iter_relocations():
                hexwidth = 8 if self.elffile.elfclass == 32 else 12
                self._emit(f'{self._format_hex(rel["r_offset"], fieldsize=hexwidth, lead0x=False)}  '
                        f'{self._format_hex(rel["r_info"], fieldsize=hexwidth, lead0x=False)} '
                        f'{describe_reloc_type(rel["r_info_type"], self.elffile)}')

                if rel['r_info_sym'] == 0:
                    self._emitline()
                    continue

                symbol = symtable.get_symbol(rel['r_info_sym'])
                if symbol['st_name'] == 0:
                    symsec = self.elffile.get_section(symbol['st_shndx'])
                    symbol_name = symsec.name
                    version = ''
                else:
                    symbol_name = symbol.name
                    version = self._symbol_version(rel['r_info_sym'])
                    version = version['name'] if version and version['name'] else ''
                symbol_name = symbol_name[:22]
                if version:
                    symbol_name += '@' + version

                self._emit(f' {self._format_hex(symbol["st_value"], fullhex=True, lead0x=False)} {symbol_name}')
                if section.is_RELA():
                    self._emit(f' {"+" if rel["r_addend"] >= 0 else "-"}{abs(rel["r_addend"]):x}')
                self._emitline()

        if not has_relocation_sections:
            self._emitline('\nThere are no relocations in this file.')

    def display_version_info(self):
        self._init_versioninfo()

        if not self._versioninfo['type']:
            self._emitline("\nNo version information found in this file.")
            return

        for section in self.elffile.iter_sections():
            if isinstance(section, GNUVerSymSection):
                self._print_version_section_header(section, 'Version symbols', lead0x=False)

                num_symbols = section.num_symbols()

                # Symbol version info are printed four by four entries
                for idx_by_4 in range(0, num_symbols, 4):
                    self._emit(f'  {idx_by_4:03x}:')

                    for idx in range(idx_by_4, min(idx_by_4 + 4, num_symbols)):
                        symbol_version = self._symbol_version(idx)
                        version_index = symbol_version['index'] if symbol_version['index'] not in ('VER_NDX_LOCAL', 'VER_NDX_GLOBAL') else 0 if symbol_version['index'] == 'VER_NDX_LOCAL' else 1
                        version_name = symbol_version['name'] if symbol_version['name'] else '(*local*)' if version_index == 0 else '(*global*)'
                        version_name = f'({version_name})' if version_index != 0 else version_name
                        visibility = 'h' if symbol_version['hidden'] else ' '
                        self._emit(f' {version_index:04x}{visibility}{version_name:13}')

                    self._emitline()

            elif isinstance(section, GNUVerDefSection):
                self._print_version_section_header(section, 'Version definition', indent=2)

                offset = 0
                for verdef, verdaux_iter in section.iter_versions():
                    verdaux = next(verdaux_iter)

                    name = verdaux.name
                    flags = describe_ver_flags(verdef['vd_flags']) + ' ' if verdef['vd_flags'] else 'none'
                    self._emitline(f'  {self._format_hex(offset, fieldsize=6, alternate=True)}: Rev: {verdef["vd_version"]}  Flags: {flags}  Index: {verdef["vd_ndx"]}  Cnt: {verdef["vd_cnt"]}  Name: {name}')

                    verdaux_offset = offset + verdef['vd_aux'] + verdaux['vda_next']
                    for idx, verdaux in enumerate(verdaux_iter, start=1):
                        self._emitline(f'  {self._format_hex(verdaux_offset, fieldsize=4)}: Parent {idx}: {verdaux.name}')
                        verdaux_offset += verdaux['vda_next']

                    offset += verdef['vd_next']

            elif isinstance(section, GNUVerNeedSection):
                self._print_version_section_header(section, 'Version needs')

                offset = 0
                for verneed, verneed_iter in section.iter_versions():
                    self._emitline(f'  {self._format_hex(offset, fieldsize=6, alternate=True)}: Version: {verneed["vn_version"]}  File: {verneed.name}  Cnt: {verneed["vn_cnt"]}')

                    vernaux_offset = offset + verneed['vn_aux']
                    for idx, vernaux in enumerate(verneed_iter, start=1):
                        flags = describe_ver_flags(vernaux['vna_flags']) + ' ' if vernaux['vna_flags'] else 'none'
                        self._emitline(f'  {self._format_hex(vernaux_offset, fieldsize=4)}:   Name: {vernaux.name}  Flags: {flags}  Version: {vernaux["vna_other"]}')
                        vernaux_offset += vernaux['vna_next']

                    offset += verneed['vn_next']


    def display_arch_specific(self):
        if self.elffile['e_machine'] == 'EM_ARM':
            self._display_arch_specific_arm()

    def display_hex_dump(self, section_spec):
        """ Display a hex dump of a section. section_spec is either a section
            number or a name.
        """
        section = self._section_from_spec(section_spec)
        if section is None:
            sys.stderr.write('readelf: Warning: Section \'%s\' was not dumped because it does not exist!\n' % (
                section_spec))
            return
        if section['sh_type'] == 'SHT_NOBITS':
            self._emitline("\nSection '%s' has no data to dump." % (
                section_spec))
            return

        self._emitline("\nHex dump of section '%s':" % section.name)
        self._note_relocs_for_section(section)
        addr = section['sh_addr']
        data = section.data()
        dataptr = 0

        while dataptr < len(data):
            bytesleft = len(data) - dataptr
            # chunks of 16 bytes per line
            linebytes = 16 if bytesleft > 16 else bytesleft

            self._emit('  %s ' % self._format_hex(addr, fieldsize=8))
            for i in range(16):
                if i < linebytes:
                    self._emit('%2.2x' % data[dataptr + i])
                else:
                    self._emit('  ')
                if i % 4 == 3:
                    self._emit(' ')

            for i in range(linebytes):
                c = data[dataptr + i : dataptr + i + 1]
                if 32 <= c[0] <= 127:
                    self._emit(chr(c[0]))
                else:
                    self._emit('.')

            self._emitline()
            addr += linebytes
            dataptr += linebytes

        self._emitline()

    def display_string_dump(self, section_spec):
        section = self._section_from_spec(section_spec)
        if section is None:
            # readelf prints the warning to stderr. Even though stderrs are not compared
            # in tests, we comply with that behavior.
            sys.stderr.write('readelf.py: Warning: Section \'%s\' was not dumped because it does not exist!\n' % (
                section_spec))
            return
        if section['sh_type'] == 'SHT_NOBITS':
            self._emitline("\nSection '%s' has no data to dump." % (
                section_spec))
            return

        self._emitline("\nString dump of section '%s':" % section.name)

        found = False
        data = section.data()
        dataptr = 0

        while dataptr < len(data):
            while dataptr < len(data) and not (32 <= data[dataptr] <= 127):
                dataptr += 1

            if dataptr >= len(data):
                break

            endptr = dataptr
            while endptr < len(data) and data[endptr] != 0:
                endptr += 1

            found = True
            self._emitline('  [%6x]  %s' % (
                dataptr, data[dataptr:endptr].decode('ascii', 'ignore')))

            dataptr = endptr

        if not found:
            self._emitline('  No strings found in this section.')
        else:
            self._emitline()

    def display_debug_dump(self, dump_what):
        """ Dump a DWARF section
        """
        self._init_dwarfinfo()
        if self._dwarfinfo is None:
            return

        set_global_machine_arch(self.elffile.get_machine_arch())

        if dump_what == 'info':
            self._dump_debug_info()
        elif dump_what == 'decodedline':
            self._dump_debug_line_programs()
        elif dump_what == 'frames':
            self._dump_debug_frames()
        elif dump_what == 'frames-interp':
            self._dump_debug_frames_interp()
        elif dump_what == 'aranges':
            self._dump_debug_aranges()
        else:
            self._emitline('debug dump not yet supported for "%s"' % dump_what)

    def _format_hex(self, addr, fieldsize=None, fullhex=False, lead0x=True,
                    alternate=False):
        if alternate:
            if addr == 0:
                lead0x = False
            else:
                lead0x = True
                fieldsize -= 2

        s = '0x' if lead0x else ''
        if fullhex:
            fieldsize = 8 if self.elffile.elfclass == 32 else 16
        if fieldsize is None:
            field = '%x'
        else:
            field = '%' + '0%sx' % fieldsize
        return s + field % addr

    def _print_version_section_header(self, version_section, name, lead0x=True,
                                    indent=1):
        if hasattr(version_section, 'num_versions'):
            num_entries = version_section.num_versions()
        else:
            num_entries = version_section.num_symbols()

        self._emitline("\n%s section '%s' contains %s entries:" %
            (name, version_section.name, num_entries))
        self._emitline('%sAddr: %s  Offset: %s  Link: %i (%s)' % (
            ' ' * indent,
            self._format_hex(
                version_section['sh_addr'], fieldsize=16, lead0x=lead0x),
            self._format_hex(
                version_section['sh_offset'], fieldsize=6, lead0x=True),
            version_section['sh_link'],
                self.elffile.get_section(version_section['sh_link']).name
            )
        )

    def _init_versioninfo(self):
        if self._versioninfo is not None:
            return

        self._versioninfo = {'versym': None, 'verdef': None,
                            'verneed': None, 'type': None}

        for section in self.elffile.iter_sections():
            if isinstance(section, GNUVerSymSection):
                self._versioninfo['versym'] = section
            elif isinstance(section, GNUVerDefSection):
                self._versioninfo['verdef'] = section
            elif isinstance(section, GNUVerNeedSection):
                self._versioninfo['verneed'] = section
            elif isinstance(section, DynamicSection):
                for tag in section.iter_tags():
                    if tag['d_tag'] == 'DT_VERSYM':
                        self._versioninfo['type'] = 'GNU'
                        break

        if not self._versioninfo['type'] and (
                self._versioninfo['verneed'] or self._versioninfo['verdef']):
            self._versioninfo['type'] = 'Solaris'


    def _symbol_version(self, nsym):
        """ Return a dict containing information on the
                or None if no version information is available
        """
        self._init_versioninfo()

        symbol_version = dict.fromkeys(('index', 'name', 'filename', 'hidden'))

        if (not self._versioninfo['versym'] or
                nsym >= self._versioninfo['versym'].num_symbols()):
            return None

        symbol = self._versioninfo['versym'].get_symbol(nsym)
        index = symbol.entry['ndx']
        if not index in ('VER_NDX_LOCAL', 'VER_NDX_GLOBAL'):
            index = int(index)

            if self._versioninfo['type'] == 'GNU':
                if index & 0x8000:
                    index &= ~0x8000
                    symbol_version['hidden'] = True

            if (self._versioninfo['verdef'] and
                    index <= self._versioninfo['verdef'].num_versions()):
                _, verdaux_iter = \
                        self._versioninfo['verdef'].get_version(index)
                symbol_version['name'] = next(verdaux_iter).name
            else:
                verneed, vernaux = \
                        self._versioninfo['verneed'].get_version(index)
                symbol_version['name'] = vernaux.name
                symbol_version['filename'] = verneed.name

        symbol_version['index'] = index
        return symbol_version

    def _section_from_spec(self, spec):
        try:
            num = int(spec)
            if num < self.elffile.num_sections():
                return self.elffile.get_section(num)
            else:
                return None
        except ValueError:
            # Not a number. Must be a name then
            return self.elffile.get_section_by_name(spec)

    def _note_relocs_for_section(self, section):
        for relsec in self.elffile.iter_sections():
            if isinstance(relsec, RelocationSection):
                info_idx = relsec['sh_info']
                if self.elffile.get_section(info_idx) == section:
                    self._emitline('  Note: This section has relocations against it, but these have NOT been applied to this dump.')
                    return

    def _init_dwarfinfo(self):
        """ Initialize the DWARF info contained in the file and assign it to
            self._dwarfinfo.
            Leave self._dwarfinfo at None if no DWARF info was found in the file
        """
        if self._dwarfinfo is not None:
            return

        if self.elffile.has_dwarf_info():
            self._dwarfinfo = self.elffile.get_dwarf_info()
        else:
            self._dwarfinfo = None

    def _dump_debug_info(self):
        """ Dump the debugging info section.
        """
        if not self._dwarfinfo.has_debug_info:
            return
        self._emitline('Contents of the %s section:\n' % self._dwarfinfo.debug_info_sec.name)

        section_offset = self._dwarfinfo.debug_info_sec.global_offset

        for cu in self._dwarfinfo.iter_CUs():
            self._emitline('  Compilation Unit @ offset %s:' %
                self._format_hex(cu.cu_offset))
            self._emitline('   Length:        %s (%s)' % (
                self._format_hex(cu['unit_length']),
                '%s-bit' % cu.dwarf_format()))
            self._emitline('   Version:       %s' % cu['version']),
            self._emitline('   Abbrev Offset: %s' % (
                self._format_hex(cu['debug_abbrev_offset']))),
            self._emitline('   Pointer Size:  %s' % cu['address_size'])
            die_depth = 0
            for die in cu.iter_DIEs():
                self._emitline(' <%s><%x>: Abbrev Number: %s%s' % (
                    die_depth,
                    die.offset,
                    die.abbrev_code,
                    (' (%s)' % die.tag) if not die.is_null() else ''))
                if die.is_null():
                    die_depth -= 1
                    continue

                for attr in itervalues(die.attributes):
                    name = attr.name
                    # Unknown attribute values are passed-through as integers
                    if isinstance(name, int):
                        name = 'Unknown AT value: %x' % name
                    self._emitline('    <%x>   %-18s: %s' % (
                        attr.offset,
                        name,
                        describe_attr_value(
                            attr, die, section_offset)))

                if die.has_children:
                    die_depth += 1

        self._emitline()

    def _dump_debug_line_programs(self):
        if not self._dwarfinfo.has_debug_info:
            return
        self._emitline('Decoded dump of debug contents of section %s:\n' % self._dwarfinfo.debug_line_sec.name)

        for cu in self._dwarfinfo.iter_CUs():
            lineprogram = self._dwarfinfo.line_program_for_CU(cu)

            cu_filename = bytes2str(lineprogram['file_entry'][0].name)
            if len(lineprogram['include_directory']) > 0:
                dir_index = lineprogram['file_entry'][0].dir_index
                if dir_index > 0:
                    dir = lineprogram['include_directory'][dir_index - 1]
                else:
                    dir = b'.'
                cu_filename = '%s/%s' % (bytes2str(dir), cu_filename)

            self._emitline('CU: %s:' % cu_filename)
            self._emitline('File name                            Line number    Starting address')
            for entry in lineprogram.get_entries():
                state = entry.state
                if state is None:
                    # Special handling for commands that don't set a new state
                    if entry.command == DW_LNS_set_file:
                        file_entry = lineprogram['file_entry'][entry.args[0] - 1]
                        if file_entry.dir_index == 0:
                            # current directory
                            self._emitline('\n./%s:[++]' % (
                                bytes2str(file_entry.name)))
                        else:
                            self._emitline('\n%s/%s:' % (
                                bytes2str(lineprogram['include_directory'][file_entry.dir_index - 1]),
                                bytes2str(file_entry.name)))
                    elif entry.command == DW_LNE_define_file:
                        self._emitline('%s:' % (
                            bytes2str(lineprogram['include_directory'][entry.args[0].dir_index])))
                elif not state.end_sequence:
                    if lineprogram['version'] < 4:
                        self._emitline('%-35s  %11d  %18s' % (
                            bytes2str(lineprogram['file_entry'][state.file - 1].name),
                            state.line,
                            '0' if state.address == 0 else
                                self._format_hex(state.address)))
                    else:
                        self._emitline('%-35s  %11d  %18s[%d]' % (
                            bytes2str(lineprogram['file_entry'][state.file - 1].name),
                            state.line,
                            '0' if state.address == 0 else
                                self._format_hex(state.address),
                            state.op_index))
                if entry.command == DW_LNS_copy:
                    # Another readelf oddity...
                    self._emitline()

    def _dump_frames_info(self, section, cfi_entries):
        self._emitline('Contents of the %s section:' % section.name)

        for entry in cfi_entries:
            if isinstance(entry, CIE):
                self._emitline('\n%08x %s %s CIE' % (
                    entry.offset,
                    self._format_hex(entry['length'], fullhex=True, lead0x=False),
                    self._format_hex(entry['CIE_id'], fieldsize=8, lead0x=False)))
                self._emitline('  Version:               %d' % entry['version'])
                self._emitline('  Augmentation:          "%s"' % bytes2str(entry['augmentation']))
                self._emitline('  Code alignment factor: %u' % entry['code_alignment_factor'])
                self._emitline('  Data alignment factor: %d' % entry['data_alignment_factor'])
                self._emitline('  Return address column: %d' % entry['return_address_register'])
                if entry.augmentation_bytes:
                    self._emitline('  Augmentation data:     {}'.format(' '.join(
                        '{:02x}'.format(ord(b))
                        for b in iterbytes(entry.augmentation_bytes)
                    )))
                self._emitline()

            elif isinstance(entry, FDE):
                self._emitline('\n%08x %s %s FDE cie=%08x pc=%s..%s' % (
                    entry.offset,
                    self._format_hex(entry['length'], fullhex=True, lead0x=False),
                    self._format_hex(entry['CIE_pointer'], fieldsize=8, lead0x=False),
                    entry.cie.offset,
                    self._format_hex(entry['initial_location'], fullhex=True, lead0x=False),
                    self._format_hex(
                        entry['initial_location'] + entry['address_range'],
                        fullhex=True, lead0x=False)))
                if entry.augmentation_bytes:
                    self._emitline('  Augmentation data:     {}'.format(' '.join(
                        '{:02x}'.format(ord(b))
                        for b in iterbytes(entry.augmentation_bytes)
                    )))

            else: # ZERO terminator
                assert isinstance(entry, ZERO)
                self._emitline('\n%08x ZERO terminator' % entry.offset)
                continue

            self._emit(describe_CFI_instructions(entry))
        self._emitline()

    def _dump_debug_frames(self):
        if self._dwarfinfo.has_EH_CFI():
            self._dump_frames_info(
                    self._dwarfinfo.eh_frame_sec,
                    self._dwarfinfo.EH_CFI_entries())
        self._emitline()

        if self._dwarfinfo.has_CFI():
            self._dump_frames_info(
                    self._dwarfinfo.debug_frame_sec,
                    self._dwarfinfo.CFI_entries())

    def _dump_debug_aranges(self):
        aranges_table = self._dwarfinfo.get_aranges()
        if aranges_table is None:
            return
        # seems redundant, but we need to get the unsorted set of entries to match system readelf
        unordered_entries = aranges_table._get_entries()

        if len(unordered_entries) == 0:
            self._emitline()
            self._emitline("Section '.debug_aranges' has no debugging data.")
            return

        self._emitline('Contents of the %s section:' % self._dwarfinfo.debug_aranges_sec.name)
        self._emitline()
        prev_offset = None
        for entry in unordered_entries:
            if prev_offset != entry.info_offset:
                if entry != unordered_entries[0]:
                    self._emitline('    %s %s' % (
                        self._format_hex(0, fullhex=True, lead0x=False),
                        self._format_hex(0, fullhex=True, lead0x=False)))
                self._emitline('  Length:                   %d' % (entry.unit_length))
                self._emitline('  Version:                  %d' % (entry.version))
                self._emitline('  Offset into .debug_info:  0x%x' % (entry.info_offset))
                self._emitline('  Pointer Size:             %d' % (entry.address_size))
                self._emitline('  Segment Size:             %d' % (entry.segment_size))
                self._emitline()
                self._emitline('    Address            Length')
            self._emitline('    %s %s' % (
                self._format_hex(entry.begin_addr, fullhex=True, lead0x=False),
                self._format_hex(entry.length, fullhex=True, lead0x=False)))
            prev_offset = entry.info_offset
        self._emitline('    %s %s' % (
                self._format_hex(0, fullhex=True, lead0x=False),
                self._format_hex(0, fullhex=True, lead0x=False)))

    def _dump_frames_interp_info(self, section, cfi_entries):
        self._emitline('Contents of the %s section:' % section.name)

        for entry in cfi_entries:
            if isinstance(entry, CIE):
                self._emitline('\n%08x %s %s CIE "%s" cf=%d df=%d ra=%d' % (
                    entry.offset,
                    self._format_hex(entry['length'], fullhex=True, lead0x=False),
                    self._format_hex(entry['CIE_id'], fieldsize=8, lead0x=False),
                    bytes2str(entry['augmentation']),
                    entry['code_alignment_factor'],
                    entry['data_alignment_factor'],
                    entry['return_address_register']))
                ra_regnum = entry['return_address_register']

            elif isinstance(entry, FDE):
                self._emitline('\n%08x %s %s FDE cie=%08x pc=%s..%s' % (
                    entry.offset,
                    self._format_hex(entry['length'], fullhex=True, lead0x=False),
                    self._format_hex(entry['CIE_pointer'], fieldsize=8, lead0x=False),
                    entry.cie.offset,
                    self._format_hex(entry['initial_location'], fullhex=True, lead0x=False),
                    self._format_hex(entry['initial_location'] + entry['address_range'],
                        fullhex=True, lead0x=False)))
                ra_regnum = entry.cie['return_address_register']

                if (len(entry.get_decoded().table) ==
                        len(entry.cie.get_decoded().table)):
                    continue

            else: # ZERO terminator
                assert isinstance(entry, ZERO)
                self._emitline('\n%08x ZERO terminator' % entry.offset)
                continue

            # Decode the table.
            decoded_table = entry.get_decoded()
            if len(decoded_table.table) == 0:
                continue

            # Print the heading row for the decoded table
            self._emit('   LOC')
            self._emit('  ' if entry.structs.address_size == 4 else '          ')
            self._emit(' CFA      ')
            decoded_table = entry.get_decoded()
            reg_order = sorted(filter(
                lambda r: r != ra_regnum,
                decoded_table.reg_order))
            if len(decoded_table.reg_order):

                # Headings for the registers
                for regnum in reg_order:
                    self._emit('%-6s' % describe_reg_name(regnum))
                self._emitline('ra      ')

                # Now include ra_regnum in reg_order to print its values
                # similarly to the other registers.
                reg_order.append(ra_regnum)
            else:
                self._emitline()

            for line in decoded_table.table:
                self._emit(self._format_hex(
                    line['pc'], fullhex=True, lead0x=False))

                if line['cfa'] is not None:
                    s = describe_CFI_CFA_rule(line['cfa'])
                else:
                    s = 'u'
                self._emit(' %-9s' % s)

                for regnum in reg_order:
                    if regnum in line:
                        s = describe_CFI_register_rule(line[regnum])
                    else:
                        s = 'u'
                    self._emit('%-6s' % s)
                self._emitline()
        self._emitline()

    def _dump_debug_frames_interp(self):
        """ Dump the interpreted (decoded) frame information from .debug_frame
        and .eh_frame sections.
        """
        if self._dwarfinfo.has_EH_CFI():
            self._dump_frames_interp_info(
                    self._dwarfinfo.eh_frame_sec,
                    self._dwarfinfo.EH_CFI_entries())
        self._emitline()

        if self._dwarfinfo.has_CFI():
            self._dump_frames_interp_info(
                    self._dwarfinfo.debug_frame_sec,
                    self._dwarfinfo.CFI_entries())

    def _display_arch_specific_arm(self):
        """ Display the ARM architecture-specific info contained in the file.
        """
        attr_sec = self.elffile.get_section_by_name('.ARM.attributes')

        if attr_sec is None:
            print("No ARM attributes section found.")
            return

        for s in attr_sec.iter_subsections():
            self._emitline("Attribute Section: %s" % s.header['vendor_name'])
            for ss in s.iter_subsubsections():
                h_val = "" if ss.header.extra is None else " ".join("%d" % x for x in ss.header.extra)
                self._emitline(describe_attr_tag_arm(ss.header.tag, h_val, None))

                for attr in ss.iter_attributes():
                    self._emit('  ')
                    self._emitline(describe_attr_tag_arm(attr.tag,
                                                        attr.value,
                                                        attr.extra))

    def _emit(self, s=''):
        """ Emit an object to output
        """
        pass
        # self.output.write(str(s))

    def _emitline(self, s=''):
        """ Emit an object to output, followed by a newline
        """
        pass

    SCRIPT_DESCRIPTION = 'Display information about the contents of ELF format files'
    VERSION_STRING = '%%(prog)s: based on pyelftools %s' % __version__

def process(file, stream=None):
    do_file_header = do_section_header = do_program_header = True
    with open(file, 'rb') as file:
        try:
            readelf = ReadElf(file, stream or sys.stdout)
            if do_file_header:
                readelf.display_file_header()
            if do_section_header:
                sections_data_list = readelf.display_section_headers(
                        show_heading=not do_file_header)
            if do_program_header:
                readelf.display_program_headers(
                        show_heading=not do_file_header)
            
                readelf.display_dynamic_tags()

                readelf.display_symbol_tables()

                readelf.display_notes()

                readelf.display_relocations()

                readelf.display_version_info()

                readelf._display_arch_specific_arm()

                readelf.display_hex_dump(1)

                readelf.display_string_dump(1)

                readelf.display_debug_dump(1)

            return sections_data_list
        except ELFError as ex:
            sys.stderr.write('ELF error: %s\n' % ex)
            sys.exit(1)

def profile_main():
    PROFFILE = 'readelf.profile'
    import cProfile
    cProfile.run('main(open("readelfout.txt", "w"))', PROFFILE)
    import pstats
    p = pstats.Stats(PROFFILE)
    p.sort_stats('cumulative').print_stats(25)