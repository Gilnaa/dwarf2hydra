#!/usr/bin/env python3
import re
import os
import sys
import argparse
from elftools.elf.elffile import ELFFile
from elftools.dwarf.die import DIE
from typing import TextIO
from collections import OrderedDict

# Type States
STATE_INITIAL = 0
STATE_IN_PROCESS = 1
STATE_FINALIZED = 2


class PaddingDetails(object):
    def __init__(self, prev_field, next_field):
        self.prev_field = prev_field
        self.next_field = next_field

    def __repr__(self):
        if self.next_field is None:
            args = (self.prev_field[2], self.prev_field[0], self.prev_field[0] + self.prev_field[1].byte_size)
            return "Trailing padding after member '%s', which spans %u:%u" % args

        args = (self.prev_field[2], self.prev_field[0], self.prev_field[0] + self.prev_field[1].byte_size,
                self.next_field[2], self.next_field[0])
        return "Padding between '%s', which spans %u:%u, and '%s', which starts at %u" % args


class Type(object):
    def __init__(self, die: DIE):
        self.source_object = die
        self.name = None
        self.byte_size = None
        self.state = STATE_INITIAL

    def finalize(self, types):
        if self.state == STATE_FINALIZED:
            return

        if self.state == STATE_IN_PROCESS:
            raise RuntimeError("Type cycle detected")

        self.state = STATE_IN_PROCESS
        self.do_finalize(types)
        self.state = STATE_FINALIZED

    def do_finalize(self, types):
        pass

    def has_padding(self):
        return False

    def get_padding_list(self):
        return []

    def get_location(self):
        node = self.source_object
        while node is not None and node.tag != 'DW_TAG_compile_unit':
            node = node.get_parent()

        if node is None:
            return None

        comp_dir = node.attributes['DW_AT_comp_dir'].value
        file_name = node.attributes['DW_AT_name'].value
        file_name = os.path.join(comp_dir, file_name)
        return file_name

    def get_hydra_type(self):
        pass


class Primitive(Type):
    def __init__(self, die: DIE):
        super().__init__(die)

        self.name = die.attributes['DW_AT_name'].value.decode('utf-8')

        self.byte_size = die.attributes['DW_AT_byte_size'].value

    def __repr__(self):
        return self.name

    def get_hydra_type(self):
        if self.name in ['float', 'double']:
            return self.name.capitalize()

        bitsize = self.byte_size * 8
        if 'unsigned' in self.name:
            return f'uint{bitsize}_t'
        else:
            return f'int{bitsize}_t'


class Struct(Type):
    def __init__(self, die: DIE):
        super().__init__(die)

        self.name = None
        if 'DW_AT_name' in die.attributes:
            self.name = die.attributes['DW_AT_name'].value.decode('utf-8')

        self.byte_size = 0
        if 'DW_AT_byte_size' in die.attributes:
            self.byte_size = die.attributes['DW_AT_byte_size'].value

        self.members = []
        for c in die.iter_children():
            if c.tag not in ['DW_TAG_member', 'DW_TAG_inheritance']:
                continue

            member_offset = c.attributes['DW_AT_data_member_location'].value
            type_num = c.attributes['DW_AT_type'].value
            if 'DW_AT_name' in c.attributes:
                member_name = c.attributes['DW_AT_name'].value.decode('utf-8') if c.tag == 'DW_TAG_member' else '<base>'
            else:
                member_name = '<unnamed>'
            self.members.append((member_offset, type_num, member_name))

    def do_finalize(self, types):
        new_members = []

        for offset, type_num, member_name in self.members:
            types[type_num].finalize(types)
            new_members.append((offset, types[type_num], member_name))

        self.members = new_members

    def has_padding(self):
        return self.byte_size != sum(map(lambda dm: dm[1].byte_size, self.members)) or \
            any(map(lambda dm: dm[1].has_padding(), self.members))

    def get_padding_list(self):
        pads = []
        # Check for padding between fields
        for i in range(len(self.members) - 1):
            cur_offset, cur_type, _ = self.members[i]
            next_offset, _, _ = self.members[i+1]
            pad_size = next_offset - cur_offset - cur_type.byte_size

            if pad_size > 0:
                pads.append(PaddingDetails(self.members[i], self.members[i+1]))

        last_member = self.members[-1]
        trailing_pad_size = self.byte_size - (last_member[0] + last_member[1].byte_size)
        if trailing_pad_size > 0:
            pads.append(PaddingDetails(last_member, None))

        return pads

    def __str__(self):
        return self.name

    def __repr__(self):
        if len(self.members) == 0:
            return self.name

        return self.name + '(%s)' % ', '.join(map(lambda m: str(m[1]), self.members))

    def get_hydra_type(self):
        return self.name


class Array(Type):
    def __init__(self, die: DIE):
        super().__init__(die)

        self.item_type = die.attributes['DW_AT_type'].value

        self.dimensions = []
        for c in die.iter_children():
            # This attribute is usually missing in VLAs (TODO: Not supported currently)
            if 'DW_AT_upper_bound' in c.attributes:
                dimension = c.attributes['DW_AT_upper_bound'].value + 1
                self.dimensions.append(dimension)

    def do_finalize(self, types):
        # assert len(self.dimensions) > 0

        self.item_type = types[self.item_type]
        self.item_type.finalize(types)
        self.byte_size = self.item_type.byte_size
        for d in self.dimensions:
            self.byte_size *= d

    def has_padding(self):
        return self.item_type.has_padding()

    def __repr__(self):
        if self.state != STATE_FINALIZED:
            return "<abstract array type>"

        base_type = "<anonymous>"
        if self.item_type.name is not None:
            base_type = self.item_type.name

        for d in self.dimensions:
            base_type += f'[{d}]'

        return base_type

    def get_hydra_type(self):
        t = self.item_type.get_hydra_type()
        for d in self.dimensions[::-1]:
            t = f'Array({d}, {t})'

        return t


class Typedef(Type):
    def __init__(self, die: DIE):
        super().__init__(die)

        self.name = die.attributes['DW_AT_name'].value.decode('utf-8')

        if 'DW_AT_type' in die.attributes:
            self.alias = die.attributes['DW_AT_type'].value
        else:
            # Probably `void`
            self.alias = None

    def do_finalize(self, types):
        if self.alias is not None:
            self.alias = types[self.alias]
            self.alias.finalize(types)
            self.byte_size = self.alias.byte_size

    def has_padding(self):
        return self.alias.has_padding()

    def __repr__(self):
        return self.name

    def get_hydra_type(self):
        return self.name


class Pointer(Type):
    def __init__(self, die: DIE):
        super().__init__(die)

        self.byte_size = die.attributes['DW_AT_byte_size'].value
        if 'DW_AT_type' in die.attributes:
            self.item_type = die.attributes['DW_AT_type'].value
        else:
            # Probably `void`
            self.item_type = None

    def do_finalize(self, types):
        if self.item_type is not None:
            self.item_type = types[self.item_type]

    def has_padding(self):
        return False

    def __repr__(self):
        return self.name

    def get_hydra_type(self):
        return 'ptr_int_for_kaplan_todo'


class ConstType(Type):
    def __init__(self, die: DIE):
        super().__init__(die)

        if 'DW_AT_type' in die.attributes:
            self.item_type = die.attributes['DW_AT_type'].value
        else:
            # Probably `void`
            self.item_type = None

    def do_finalize(self, types):
        if self.item_type is not None:
            self.item_type = types[self.item_type]
        self.byte_size = self.item_type.byte_size

    def has_padding(self):
        return self.item_type.has_padding()

    def __repr__(self):
        return self.name

    def get_hydra_type(self):
        return self.item_type.get_hydra_type()


class EnumType(Type):
    def __init__(self, die: DIE):
        super().__init__(die)

        self.name = '<unnamed-enum>'
        if 'DW_AT_name' in die.attributes:
            self.name = die.attributes['DW_AT_name'].value.decode('utf-8')

        self.literals = OrderedDict()
        for lit in die.iter_children():
            assert lit.tag == 'DW_TAG_enumerator'
            name = lit.attributes['DW_AT_name'].value.decode('utf-8')
            value = lit.attributes['DW_AT_const_value'].value
            self.literals[name] = value

        if 'DW_AT_type' in die.attributes:
            self.item_type = die.attributes['DW_AT_type'].value
        else:
            # Probably `void`
            assert False, 'TODO'

    def do_finalize(self, types):
        if self.item_type is not None:
            self.item_type = types[self.item_type]
            self.item_type.finalize(types)
            self.byte_size = self.item_type.byte_size

    def has_padding(self):
        return False

    def __repr__(self):
        return self.name

    def get_hydra_type(self):
        return self.name


class UnsupportedType(Type):
    def __init__(self, die: DIE):
        super().__init__(die)
        self.die = die

    def do_finalize(self, types):
        pass

    def has_padding(self):
        return False

    def __repr__(self):
        return self.name

    def get_hydra_type(self):
        return None


def parse_dwarf_info(elf):
    translation_units = {}
    for cu in elf.get_dwarf_info().iter_CUs():
        types = {}
        cu_name = cu.get_top_DIE().attributes['DW_AT_name'].value.decode('utf-8')
        print('\x1b[32m\x1b[1mProcessing %s\x1b[0m' % cu_name, file=sys.stderr)

        # First, map top level types
        for die in cu.iter_DIEs():
            common_types = {
                'DW_TAG_structure_type': Struct,
                'DW_TAG_class_type': Struct,
                'DW_TAG_base_type': Primitive,
                'DW_TAG_typedef': Typedef,
                'DW_TAG_array_type': Array,
                'DW_TAG_pointer_type': Pointer,
                'DW_TAG_const_type': ConstType,
                'DW_TAG_enumeration_type': EnumType,
            }

            offset = die.offset - cu.cu_offset
            if die.tag in common_types:
                assert offset not in types
                types[offset] = common_types[die.tag](die)
            else:
                types[offset] = UnsupportedType(die)

        translation_units[cu] = types

    return translation_units


def generate_hydra_file(structs, fp: TextIO):
    # Typedefs are generated only if used.
    typedefs = []
    struct_lines = []

    for struct in structs:

        padding_counter = 0
        last_ending_offset = 0

        # Adding 2 empty lines in order to comply w/ PEP8
        struct_lines.append(f'\n\nclass {struct.name}(Struct):')

        for offset, member_type, member_name in struct.members:
            # Collect typedefs, but skip definition of standard types.
            if isinstance(member_type, Typedef) and not re.match('u?int[0-9]{1,2}_t', member_type.name):
                typedefs.append(f'{member_type.name} = {member_type.alias.get_hydra_type()}')

            if last_ending_offset < offset:
                struct_lines.append(f'    _padding_{padding_counter} = Pad({offset - last_ending_offset})')
                padding_counter += 1
            last_ending_offset = offset + member_type.byte_size

            struct_lines.append(f'    {member_name} = {member_type.get_hydra_type()}')
    fp.write('from hydras import *\n\n')
    fp.write('\n'.join(typedefs + struct_lines))


def main():
    args = argparse.ArgumentParser(description='Parses an ELF file with DWARF debug symbols and generates Hydra '
                                               'definitions for the selected structs.'
                                               ''
                                               'If no whitelist patterns are specified, all parseable structs will be printed.')
    args.add_argument('input_file', help='Path to the input ELF file.')
    args.add_argument('--whitelist', help='A regex pattern used to choose structs for generation.'
                                          'May be specified multiple times.',
                      type=str, action='append', default=[])
    args.add_argument('-o', '--output', help='Name of output file.')
    args = args.parse_args()

    patterns = [re.compile(pat) for pat in args.whitelist]

    with open(args.input_file, 'rb') as f:
        elf = ELFFile(f)
        if not elf.has_dwarf_info():
            print("Object file has no dwarf info!", file=sys.stderr)
            sys.exit(1)

        all_structs = []
        for cu, cu_types in parse_dwarf_info(elf).items():
            structs = (t for t in cu_types.values() if isinstance(t, Struct))
            if len(patterns) > 0:
                structs = (t for t in structs if t.name is not None and any(p.match(t.name) for p in patterns))

            # Translate type offset into object-references.
            for s in structs:
                s.finalize(cu_types)
                all_structs.append(s)

        output = sys.stdout
        if args.output is not None:
            output = open(args.output, 'w')

        generate_hydra_file(all_structs, output)


if __name__ == '__main__':
    main()