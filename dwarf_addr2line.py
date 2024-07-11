from elftools.elf.elffile import ELFFile
from elftools.dwarf.ranges import BaseAddressEntry 
from elftools.dwarf.descriptions import describe_form_class
from collections import namedtuple
import argparse
import os

CodeLocation = namedtuple('CodeLocation', ['name', 'file', 'line'])
LowHighPair = namedtuple('LowHighPair', ['lowpc', 'highpc'])

# Command line flags
# for printing full filepaths rather than file basenames
fullnames = False
# for printing "linkage" C++ mangled names
manglednames = False 

def load_dwarf_info(filename):
    with open(filename, 'rb') as f:
        elffile = ELFFile(f)
        if not elffile.has_dwarf_info():
            raise ValueError('This file does not contain DWARF debugging information.')
        dwarfinfo = elffile.get_dwarf_info()
        return dwarfinfo

def file_entry_to_directory(file_entry, lineprogram):
    delta = 1 if lineprogram.header.version < 5 else 0
    dir_index = file_entry.dir_index - delta
    includes = lineprogram.header.include_directory
    if dir_index >= 0:
        file_dir = includes[dir_index].decode('utf-8')
        if file_dir.startswith('.'):
            file_dir = os.path.join(_cu_comp_file_dir(cu), file_dir)
    else:
        file_dir = _cu_comp_file_dir(cu)
    return file_dir

def find_line_info(dwarfinfo, cu, address):
    if not hasattr(cu, '_lineprogram'):
        cu._lineprogram = dwarfinfo.line_program_for_CU(cu)
    if cu._lineprogram:
        delta = 1 if cu._lineprogram.header.version < 5 else 0
        prev_state = None
        for entry in cu._lineprogram.get_entries():
            if entry.state is None:
                continue
            if prev_state and prev_state.address <= address and address < entry.state.address:
                file_entry = cu._lineprogram.header.file_entry[prev_state.file - delta]
                file_name = file_entry.name.decode('utf-8')
                if fullnames:
                    file_dir = file_entry_to_directory(file_entry, cu._lineprogram)
                    file_name = os.path.join(file_dir, file_name)
                return file_name, prev_state.line
            else:
                prev_state = entry.state
            if entry.state.end_sequence:
                prev_state = None
    return None, None

def print_die(die):
    cu_offset = die.cu.cu_offset
    s = f'DIE {die.tag} has_children={die.has_children} {die.offset - (cu_offset + 1)}\n'
    for attrname, attrval in die.attributes.items():
        adjusted_offset = getattr(attrval, 'offset') - (cu_offset + 1)
        s += '    |%-18s:  %s adjusted_offset: %d\n' % (attrname, attrval, adjusted_offset)
    print(s)

def file_index_to_str(attr, die):
    cu = die.cu
    if not hasattr(cu, '_lineprogram'):
        cu._lineprogram = die.dwarfinfo.line_program_for_CU(cu)
    if not cu._lineprogram:
        raise DWARFError('Compilation unit has no line program')
    delta = 1 if cu._lineprogram.header.version < 5 else 0
    file_entry = cu._lineprogram.header.file_entry[attr.value - delta]
    file_name = file_entry.name.decode('utf-8')
    if fullnames:
        file_dir = file_entry_to_directory(file_entry, cu._lineprogram)
        file_name = os.path.join(file_dir, file_name)
    return file_name

def get_die_name(die):
    if 'DW_AT_name' in die.attributes:
        if manglednames and 'DW_AT_linkage_name' in die.attributes:
            return die.attributes['DW_AT_linkage_name'].value.decode('utf-8')
        else:
            return die.attributes['DW_AT_name'].value.decode('utf-8')
    elif 'DW_AT_abstract_origin' in die.attributes:
        ref_die = die.get_DIE_from_attribute('DW_AT_abstract_origin')
        return get_die_name(ref_die)
    elif 'DW_AT_specification' in die.attributes:
        ref_die = die.get_DIE_from_attribute('DW_AT_specification')
        return get_die_name(ref_die)
    else:
        raise ValueError('Unable to find function name in DIE or its references.')

def get_cu_base(cu):
    top_die = cu.get_top_DIE()
    attr = top_die.attributes
    if 'DW_AT_low_pc' in attr:
        return attr['DW_AT_low_pc'].value
    elif 'DW_AT_entry_pc' in attr:
        return attr['DW_AT_entry_pc'].value
    else:
        raise ValueError("Can't find the base IP (low_pc) for a CU")

def is_addr_in_die_range(die, address, range_lists):
    # Build a list of lowpc/highpc pairs to check.
    low_high_pairs = []

    # If these tags are present there will be a single pair.
    if 'DW_AT_low_pc' in die.attributes and 'DW_AT_high_pc' in die.attributes:
        lowpc = die.attributes['DW_AT_low_pc'].value
        highpc_attr = die.attributes['DW_AT_high_pc']
        highpc_attr_class = describe_form_class(highpc_attr.form)
        if highpc_attr_class == 'address':
            highpc = highpc_attr.value
        elif highpc_attr_class == 'constant':
            highpc = lowpc + highpc_attr.value
        else:
            raise DWARFError(f'invalid DW_AT_high_pc class: {highpc_attr_class}')
        low_high_pairs.append(LowHighPair(
            lowpc = lowpc,
            highpc = highpc))
    
    # DW_AT_ranges can refer to several pairs
    elif 'DW_AT_ranges' in die.attributes:
        rangelist = range_lists.get_range_list_at_offset(die.attributes['DW_AT_ranges'].value)
        if range_lists.version < 5: 
            base_ip = get_cu_base(die.cu)
            base_entry = BaseAddressEntry(0, base_ip)
        for range_entry in rangelist:
            if isinstance(range_entry, BaseAddressEntry):
                base_entry = range_entry
                continue
            if range_entry.is_absolute is True:
                lowpc = range_entry.begin_offset
                highpc = range_entry.end_offset
            else:
                lowpc = base_entry.base_address + range_entry.begin_offset
                highpc = base_entry.base_address + range_entry.end_offset
            low_high_pairs.append(LowHighPair(
                lowpc = lowpc,
                highpc = highpc))

    # Now check each pair
    for addr_range in low_high_pairs:
        if addr_range.lowpc <= address < addr_range.highpc:
            return True

    return False

# Recursively search for matching inlined subroutines and append to results
def inline_search(die, address, range_lists, results):
    if die.has_children:
        for child in die.iter_children():
            if child.tag == 'DW_TAG_inlined_subroutine':
                if is_addr_in_die_range(child, address, range_lists):
                    results.append(CodeLocation(
                        name = get_die_name(child),
                        file = file_index_to_str(child.attributes['DW_AT_call_file'], child),
                        line = child.attributes['DW_AT_call_line'].value))
                    # If we found a match we only need continue our search on this subtree
                    inline_search(child, address, range_lists, results)
                    return True
            if inline_search(child, address, range_lists, results):
                # If this branch of the search hit, we're done
                return True
    return False 

# Returns a list of CodeLocations for the given address
# File and line are set to the calling file and line when there is inlining,
# otherwise these are None
def find_function_info(dwarfinfo, range_lists, cu, address):
    results = []
    top_die = cu.get_top_DIE()
    for die in top_die.iter_children():
        if die.tag == 'DW_TAG_subprogram':
            if is_addr_in_die_range(die, address, range_lists):
                results.append(CodeLocation(
                    name = get_die_name(die),
                    file = None,
                    line = None))
                # Found a match, now look for inlines
                inline_search(die, address, range_lists, results)
                break
    # Reverse to return innermost inline first
    return results[::-1]

def main(filename, addresses):
    dwarfinfo = load_dwarf_info(filename)
    aranges = dwarfinfo.get_aranges()
    range_lists = dwarfinfo.range_lists()
    for address in addresses:
        cu_offset = aranges.cu_offset_at_addr(address)
        if cu_offset is None:
            print(f'0x{address:x}: No compilation unit found for this address')
            continue
        cu = dwarfinfo.get_CU_at(cu_offset)
        # Innermost file and line info come from DWARF lineinfo
        file_name, line = find_line_info(dwarfinfo, cu, address)
        # Function names and any inlining information comes from DWARF debug info
        locations = find_function_info(dwarfinfo, range_lists, cu, address)
        if locations is not None:
            for i, loc in enumerate(locations):
                if i == 0:
                    print(f'0x{address:x}: {loc.name} at {file_name}:{line}')
                else:
                    # The calling file and line for this inline will be in the
                    # previous result
                    prev_loc = locations[i-1]
                    print(f' (inlined by) {loc.name} at {prev_loc.file}:{prev_loc.line}')
        else:
            print(f'0x{address:x}: ?? at {file_name}:{line}')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='convert addresses to function names, file and line number')
    parser.add_argument('-s', '--fullnames', action='store_true', help='Print full filepaths rather than basenames')
    parser.add_argument('-m', '--manglednames', action='store_true', help='Print mangled linkage names.')
    parser.add_argument('filename', help='ELF binary filename')
    parser.add_argument('addresses', nargs='+', type=lambda x: int(x, 0), help='addresses to symbolicate')
    args = parser.parse_args()
    if args.fullnames:
        fullnames = True
    if args.manglednames:
        manglednames = True
    main(args.filename, args.addresses)
