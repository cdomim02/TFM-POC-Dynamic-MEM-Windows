import enum
import logging
import string
import struct
import math

from typing import Generator, List, Tuple, Union, Dict

from volatility3.framework import exceptions, interfaces, renderers, constants, contexts, symbols, objects
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols.windows import pdbutil

from volatility3.plugins.windows import pslist, vadinfo, info

from capstone import *
from collections import Counter
import re

vollog = logging.getLogger(__name__)

""" Flags for HEAP_ENTRY when backend allocated """
class HEAP_ENTRY_FLAGS(enum.IntFlag):
    BUSY             = 0x01
    EXTRA_PRESENT    = 0x02
    FILL_PATTERN     = 0x04
    VIRTUAL_ALLOC    = 0x08
    LAST_ENTRY       = 0x10
    SETTABLE_FLAG1   = 0x20
    SETTABLE_FLAG2   = 0x40
    SETTABLE_FLAG3   = 0x80

HEAP_ENTRY_FLAGS_DISPLAY_NAMES = {
    HEAP_ENTRY_FLAGS.BUSY:           "busy",
    HEAP_ENTRY_FLAGS.EXTRA_PRESENT:  "extra",
    HEAP_ENTRY_FLAGS.FILL_PATTERN:   "fill",
    HEAP_ENTRY_FLAGS.VIRTUAL_ALLOC:  "internal",
    HEAP_ENTRY_FLAGS.LAST_ENTRY:     "last",
    HEAP_ENTRY_FLAGS.SETTABLE_FLAG1: "user_flag1",
    HEAP_ENTRY_FLAGS.SETTABLE_FLAG2: "user_flag2",
    HEAP_ENTRY_FLAGS.SETTABLE_FLAG3: "user_flag3",
}

""" Flags related to the Low-Fragmentation Heap (LFH) """
LFH_HEAP_ACTIVE     = 0x02
LFH_HEAP_ENTRY_FREE = 0x80

class AnonymizedPlugin(interfaces.plugins.PluginInterface):
    """Lists the NT heap entries of processes from a Windows memory image, supporting both back end and front end (LFH) layers."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)
    _md_capstone = None

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="pdbutil", component=pdbutil.PDBUtility, version=(1, 0, 0)
            ),
            requirements.PluginRequirement(
                name="vadinfo", plugin=vadinfo.VadInfo, version=(2, 0, 0)
            ),
            requirements.PluginRequirement(
                name="info", plugin=info.Info, version=(2, 0, 0)
            ),
            requirements.PluginRequirement(
                name="pslist", plugin=pslist.PsList, version=(3, 0, 0)
            ),
            requirements.ListRequirement(
                name="pid",
                element_type=int,
                description="Process ID to include (all other processes are excluded)",
                optional=True,
            ),
            requirements.ListRequirement(
                name="dump",
                element_type=int,
                description="Virtual memory address of the heap entry to dump",
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="dump-all",
                description="Extract all heap entries",
                default=False,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="detect-attacks",
                description="Analyze heap entries to detect possible attacks",
                optional=True,
                default=False
            ),
        ]

    def _is_win_8_1_to_11(self, kuser: objects.StructType) -> bool:
        return ((int(kuser.NtMajorVersion) == 10) and (int(kuser.NtMinorVersion) == 0)) or ((int(kuser.NtMajorVersion) == 6) and (int(kuser.NtMinorVersion) == 3))

    def _is_win_8(self, kuser: objects.StructType) -> bool:
        return (int(kuser.NtMajorVersion) == 6) and (int(kuser.NtMinorVersion) == 2)

    def _is_win_vista_to_8(self, kuser: objects.StructType) -> bool:
        return (int(kuser.NtMajorVersion) == 6) and (int(kuser.NtMinorVersion) in (0, 1))

    def _is_win_below_vista(self, kuser: objects.StructType) -> bool:
        return int(kuser.NtMajorVersion) < 6

    def _flag_to_string(self, flag: int) -> str:
        flag_encoded = HEAP_ENTRY_FLAGS(flag)

        if HEAP_ENTRY_FLAGS.BUSY in flag_encoded:
            string = HEAP_ENTRY_FLAGS_DISPLAY_NAMES.get(HEAP_ENTRY_FLAGS.BUSY)
        else:
            string = "free"

        for f in list(HEAP_ENTRY_FLAGS)[1:]:
            if f in flag_encoded:
                string += f" {HEAP_ENTRY_FLAGS_DISPLAY_NAMES.get(f, f.name)}"

        return string

    def _is_addr_uncommitted(self, addr: int, uncommitted_regions: [(int, int)]) -> int:
        """ Accessing a reserved memory throws a page fault exception, avoid accessing memory that is not committed """
        for uncommitted_region in uncommitted_regions:
            if (addr >= uncommitted_region[0]) and (addr <= uncommitted_region[0] + uncommitted_region[1]):
                return uncommitted_region[1]

        return 0

    def _get_lfh_key(self, ntdll: contexts.Module, layer_name: str) -> int:
        kernel = self.context.modules[self.config["kernel"]]

        lfh_key_address = ntdll.offset + ntdll.get_symbol("RtlpLFHKey").address

        is_kernel_64 = symbols.symbol_table_is_64bit(self.context, kernel.symbol_table_name)

        if is_kernel_64:
            lfh_key_content = self.context.layers[layer_name].read(lfh_key_address, 8)
            return struct.unpack("<Q", lfh_key_content)[0]
        else:
            lfh_key_content = self.context.layers[layer_name].read(lfh_key_address, 4)
            return struct.unpack("<I", lfh_key_content)[0]

    def _find_ntdll_by_vad(self, proc: interfaces.context.ContextInterface) -> Tuple[int, int]:
        """ Returns (Offset, Size) of the VAD corresponding to the ntdll.dll of a given process """
        kernel = self.context.modules[self.config["kernel"]]

        for vad in proc.get_vad_root().traverse():
            filename = vad.get_file_name()

            if isinstance(filename, str) and filename.lower().endswith("\\ntdll.dll"):
                vad_protection = vad.get_protection(
                    vadinfo.VadInfo.protect_values(
                        self.context,
                        kernel.layer_name,
                        kernel.symbol_table_name,
                    ),
                    vadinfo.winnt_protections,
                )

                """ Basic check of the usual DLL protection when loaded normally """
                if vad_protection == "PAGE_EXECUTE_WRITECOPY":
                    return (vad.get_start(), vad.get_size())
                else:
                    pid = proc.UniqueProcessId
                    proc_name = utility.array_to_string(proc.ImageFileName)
                    vollog.warning(f"{proc_name} ({pid})\t: Skipping unusual ntdll.dll at {vad.get_start():#x} (VAD protection {vad_protection})")

        return (None, None)

    def _load_ntdll_symbols(self) -> contexts.Module:
        for proc in pslist.PsList.list_processes(
                    context=self.context,
                    kernel_module_name=self.config["kernel"],
                    filter_func=pslist.PsList.create_pid_filter(None),
                ):            
            """
            Let's assume that the same legitimate ntdll.dll is running in each process. For our purposes,
            just finding one should be enough
            """
            (ntdll_base, ntdll_size) = self._find_ntdll_by_vad(proc)

            if (ntdll_base is not None) and (ntdll_size is not None):
                proc_layer_name = proc.add_process_layer()

                try:
                    vollog.debug(f"Trying to obtaining symbols for ntdll.dll from {utility.array_to_string(proc.ImageFileName)} ({proc.UniqueProcessId})...")

                    ntdll_symbols = pdbutil.PDBUtility.symbol_table_from_pdb(
                                    self.context,
                                    interfaces.configuration.path_join(self.config_path, "ntdll"),
                                    proc_layer_name,
                                    "ntdll.pdb",
                                    ntdll_base,
                                    ntdll_size,
                                )

                    return self.context.module(
                        ntdll_symbols, layer_name=proc_layer_name, offset=ntdll_base
                    )
                except exceptions.VolatilityException:
                    continue

        return None

    def _generate_output(self, proc_name: str, pid: objects.Pointer, layer_name: str, heap_entry: objects.StructType, heap_entry_size: int, granularity: int) -> Tuple[str, str, bytes]:
        try:
            """
            If the entry size is less than the granularity, the size is the actual size of the data
            appended to the _HEAP_ENTRY. This can only happen on the LFH layer, on the backend layer
            the minimum size is 2 * granularity due to memory alignment
            """
            if (heap_entry_size - granularity) < granularity:
                user_data_size = heap_entry_size
                user_data_offset = heap_entry.vol.offset
            else:
                user_data_size = heap_entry_size - granularity
                user_data_offset = heap_entry.vol.offset + granularity

            """ Read the actual user data """
            data = self.context.layers[layer_name].read(user_data_offset, user_data_size)

            """ Remove the HEAP_ENTRY header """
            if (heap_entry_size - granularity) > granularity:
                data = data[granularity:]

            file_output = "Disabled"

            if self.config["dump-all"] or (heap_entry.vol.offset in self.config["dump"]):
                file_output = f"{pid}.heap.{heap_entry.vol.offset:x}.dmp"
                with open(file_output, "wb") as f:
                    f.write(data)

            """ Display maximum 0x30 bytes for demonstration purposes, if less, display actual data based on the heap entry size """
            decoded_size = user_data_size if user_data_size < 0x30 else 0x30

            decoded_data = "".join([c if (c in string.printable) and (c not in string.whitespace) else "." for c in data[:decoded_size].decode("ascii", errors="replace").replace("\ufffd", ".")])
        except exceptions.InvalidAddressException:
            """ We retrieved the _HEAP_ENTRY but not the data, we can still traverse the following _HEAP_ENTRYs """
            vollog.debug(f"{proc_name} ({pid})\t: Unable to read _HEAP_ENTRY data @ {heap_entry.vol.offset:#x}")
            file_output = "Unavailable"
            decoded_data = "????"
            data ="????"

        return (decoded_data, file_output, data)

    def _get_lfh_entries(self, proc_name: str, pid: objects.Pointer, ntdll: contexts.Module, layer_name: str, lfh_heap_address: objects.Pointer) -> Dict[int, Dict[str, Union[int, List[Union[objects.StructType, int]]]]]:
        lfh_entries = {}

        kernel = self.context.modules[self.config["kernel"]]
        kuser = info.Info.get_kuser_structure(self.context, self.config["kernel"])

        _LIST_ENTRY = kernel.get_type("_LIST_ENTRY")
        _HEAP_ENTRY = kernel.get_type("_HEAP_ENTRY")
        granularity = _HEAP_ENTRY.size
        """ The key will be used later to decode the _HEAP_USERDATA_HEADER information """
        if self._is_win_8_1_to_11(kuser):
            LFH_KEY = self._get_lfh_key(ntdll, layer_name)

        _LFH_HEAP = ntdll.get_type("_LFH_HEAP")
        _LFH_BLOCK_ZONE = ntdll.get_type("_LFH_BLOCK_ZONE")
        _HEAP_SUBSEGMENT = ntdll.get_type("_HEAP_SUBSEGMENT")

        lfh_heap = self.context.object(_LFH_HEAP, layer_name, lfh_heap_address)
        block_zones = self.context.object(_LIST_ENTRY, layer_name, lfh_heap.SubSegmentZones.vol.offset).to_list(f"{ntdll.symbol_table_name}{constants.BANG}_LFH_BLOCK_ZONE", "ListEntry")

        for block_zone in block_zones:
            vollog.debug(f'{proc_name} ({pid})\t: _LFH_BLOCK_ZONE\t\t\t: {block_zone.vol.offset:#x}')

            subsegment_size = _HEAP_SUBSEGMENT.size
            subsegment_addr = block_zone.vol.offset + (granularity * 2)

            if self._is_win_8_1_to_11(kuser):
                end_block_zone = subsegment_addr + (subsegment_size * block_zone.NextIndex)
            else:
                end_block_zone = block_zone.FreePointer

            no_subsegments = (end_block_zone - subsegment_addr) // subsegment_size

            subsegment_pointers = self.context.object(
                f"{kernel.symbol_table_name}{constants.BANG}array",
                layer_name,
                subsegment_addr,
                count=no_subsegments,
                subtype=_HEAP_SUBSEGMENT
            )

            for subsegment in subsegment_pointers:
                vollog.debug(f'{proc_name} ({pid})\t: _HEAP_SUBSEGMENT\t\t: {subsegment.vol.offset:#x}')
                user_blocks = subsegment.UserBlocks
                vollog.debug(f'{proc_name} ({pid})\t: _HEAP_USERDATA_HEADER\t\t: {user_blocks:#x}')

                try:
                    if self._is_win_8_1_to_11(kuser):
                        """ Decode the fields of _HEAP_USERDATA_HEADER.EncodedOffsets """
                        encoded_offsets = user_blocks.EncodedOffsets.StrideAndOffset ^ user_blocks ^ lfh_heap.vol.offset ^ LFH_KEY
                        """ Get the relative address of the first _HEAP_ENTRY """
                        first_allocation_offset = encoded_offsets & 0xffff
                        """ In an LFH segment, all _HEAP_ENTRYs have the same size """
                        block_stride = ((encoded_offsets ^ user_blocks.EncodedOffsets.BlockStride) >> 0x10) & 0xffff
                        heap_entry_addr = user_blocks + first_allocation_offset
                    elif self._is_win_8(kuser):
                        block_stride = subsegment.BlockSize * granularity
                        heap_entry_addr = user_blocks + user_blocks.FirstAllocationOffset
                    else:                            
                        block_stride = subsegment.BlockSize * granularity
                        heap_entry_addr = user_blocks + _LFH_BLOCK_ZONE.size

                    """ Simply save the _HEAP_ENTRYs to view them later along with the backend heap entries """
                    heap_entries = []

                    for _ in range(subsegment.BlockCount):
                        try:
                            heap_entry = self.context.object(_HEAP_ENTRY, layer_name, heap_entry_addr)
                            heap_entries.append(heap_entry)
                        except exceptions.InvalidAddressException:
                            """ We know the _HEAP_ENTRY size anyway, continue traversing """
                            vollog.debug(f"{proc_name} ({pid})\t: Unable to read LFH _HEAP_ENTRY data @ {heap_entry_addr:#x}")
                            """ We are inserting an int instead of a StructType """
                            heap_entries.append(heap_entry_addr)

                        heap_entry_addr += block_stride

                    lfh_entries[int(user_blocks)] = {"block_stride": block_stride, "heap_entries": heap_entries}
                except (exceptions.InvalidAddressException, AssertionError):
                    vollog.warning(f'{proc_name} ({pid})\t: Unable to parse LFH _HEAP_SUBSEGMENT @ {subsegment.vol.offset:#x}')

        return lfh_entries
    

    def check_overflow(self, flag: int, heap_entry_size: int, heap_entry_addr: objects.Pointer, current_entry_by_size_of_previous_entry: objects.Pointer, last_entry_addr: objects.Pointer) -> Tuple[str, str]:
        flag_encoded = HEAP_ENTRY_FLAGS(flag)
        detected_attack = "[Overflow:] "

        # Check flags related with free state
        """ User flags are usually cleared when a heap entry is freed """
        if (HEAP_ENTRY_FLAGS.BUSY not in flag_encoded) and ((HEAP_ENTRY_FLAGS.SETTABLE_FLAG1 in flag_encoded) or 
                                                            (HEAP_ENTRY_FLAGS.SETTABLE_FLAG2 in flag_encoded) or 
                                                            (HEAP_ENTRY_FLAGS.SETTABLE_FLAG3 in flag_encoded)):
            detected_attack += "user flags in a free entry; "

        """ Allocations to VirtualAlloc for a large size are not stored in traditional
            bins when freed, so these spaces cannot be marked as free """
        if (HEAP_ENTRY_FLAGS.BUSY not in flag_encoded) and (HEAP_ENTRY_FLAGS.VIRTUAL_ALLOC in flag_encoded):
            detected_attack += "free entry mark as internal; "

        """ When freeing an entry from the heap, the manager stops referencing extra headers """
        if (HEAP_ENTRY_FLAGS.BUSY not in flag_encoded) and (HEAP_ENTRY_FLAGS.EXTRA_PRESENT in flag_encoded):
            detected_attack += "free entry with extra header; "

        # Check problems related with last entry flag
        """ When freeing an entry from the heap, the manager stops referencing extra headers """
        next_heap_entry_addr = heap_entry_addr + heap_entry_size
        if next_heap_entry_addr != last_entry_addr and (HEAP_ENTRY_FLAGS.LAST_ENTRY in flag_encoded):
            detected_attack += "non-last entry marked as last; "
                
        # Check problems related to size and next heap entry
        """ The next entry must be located after the current one, and its size must be adequate to achieve this """
        if (current_entry_by_size_of_previous_entry != 0) and (heap_entry_addr != current_entry_by_size_of_previous_entry):
            detected_attack += "previous entry size jump is incorrect; "

        if detected_attack == "[Overflow:] ":
            return ("False", "Undetected Attack")
        else:
            return ("Overflow", detected_attack)


    def init_capstone(self, proc: interfaces.context.ContextInterface):
        kernel = self.context.modules[self.config["kernel"]]
        is_kernel_64 = symbols.symbol_table_is_64bit(self.context, kernel.symbol_table_name)

        """ Select correct code architecture mode """
        if is_kernel_64 and proc.get_is_wow64():
            mode = CS_MODE_32
        elif not is_kernel_64:
            mode = CS_MODE_32
        else:
            mode = CS_MODE_64

        """ Init capstone to current process  """
        self._md_capstone = Cs(CS_ARCH_X86, mode)


    def asm_code_entropy(self, asm_code):
        """ Shannon entropy to measure the variability of assembly language instructions """
        mnemonics = [ins.mnemonic for ins in asm_code]
        freq = Counter(mnemonics)
        total = len(mnemonics)

        entropy = 0.0
        for count in freq.values():
            p = count / total
            entropy -= p * math.log2(p)

        return entropy
    
    def nops_sum(self, asm_code) -> int:
        total_nops = 0

        """ Count total number of NOPs, include classic NOPS and camouflaged NOPS """
        for ins in asm_code: 
            op_code = ins.mnemonic
            ops = ins.op_str.replace(" ", "")

            # Classic NOPs like 0x90 or NOPs multi-byte like 0F 1F 00
            if op_code == "nop":
                total_nops += 1

            # xchg reg, reg (tipical NOP if both ops are the same)
            elif op_code == "xchg":
                # mismo operando a ambos lados
                ops_parts = ops.split(",")
                if len(ops_parts) == 2 and ops_parts[0] == ops_parts[1]:
                    total_nops += 1

            # mov reg, reg (tipical NOP if both ops are the same)
            elif op_code == "mov":
                ops_parts = ops.split(",")
                if len(ops_parts) == 2 and ops_parts[0] == ops_parts[1]:
                    total_nops += 1

            # lea reg, [reg+0] or lea reg, [reg] (load the same address)
            elif op_code == "lea":
                ops_parts = ops.split(",")
                if len(ops_parts) == 2:
                    dst, src = ops_parts
                    # patterns like: [rax], [rax+0], [rax+0x0]
                    if re.fullmatch(rf"\[{dst}(\+0x?0)?\]", src):
                        total_nops += 1

            # add/sub reg, 0 (arithmetic operations with 0, result does not change)
            elif op_code in ("add", "sub", "or", "and", "xor"):
                ops_parts = ops.split(",")
                if len(ops_parts) == 2 and ops_parts[1] in ("0", "0x0"):
                    total_nops += 1

        return total_nops
        

    def check_spray(self, data) -> Tuple[str, str]:
        """ Data can be ???? if have problems when reading """
        if isinstance(data, (bytes, bytearray)):
            asm_code = list(self._md_capstone.disasm(data, 0x1000))

            """ If there is no code, we assume that there is no spraying """
            if not asm_code: 
                return ("False", "Undetected Attack")
            else:
                """ Spraying usually consists of a payload preceded by NOP sleds (repetitive instructions).
                    Low entropy usually means highly repetitive code that may suggest a large number of NOPs. 
                    It is necessary to check that this low entropy is actually due to a high presence of NOPs. """
                code_entropy = self.asm_code_entropy(asm_code)
                number_of_nops = self.nops_sum(asm_code)
                nops_rate = number_of_nops / len(asm_code)
                if code_entropy < 0.5 and nops_rate > 0.6:
                    return ("Spraying", f"[Spraying:] {number_of_nops} NOPs of {len(asm_code)} total asm instrutions")

        return ("False", "Undetected Attack")            
        

    def is_attacked(self, flag: int, heap_entry_size: int, heap_entry_addr: objects.Pointer, current_entry_by_size_of_previous_entry: objects.Pointer, last_entry_addr: objects.Pointer, data) -> Tuple[str, str]:
        (detected_attack_overflow, attack_details_overflow) = self.check_overflow(flag, heap_entry_size, heap_entry_addr, current_entry_by_size_of_previous_entry, last_entry_addr)
        (detected_attack_spray, attack_details_spray) = self.check_spray(data)

        if detected_attack_overflow == "False":
            return (detected_attack_spray, attack_details_spray)
        elif detected_attack_spray == "False":
            return (detected_attack_overflow, attack_details_overflow)
        else:
            return (detected_attack_overflow + "; " + detected_attack_spray, attack_details_overflow + attack_details_spray)


    def _generator(self, procs: Generator[interfaces.objects.ObjectInterface, None, None]):
        kernel = self.context.modules[self.config["kernel"]]
        kuser = info.Info.get_kuser_structure(self.context, self.config["kernel"])

        """ Minimum supported is Windows Vista """
        if self._is_win_below_vista(kuser):
            vollog.error(f"Windows NT {kuser.NtMajorVersion:d}.{kuser.NtMinorVersion:d} found\t: Windows image not supported, minimum supported is Windows Vista (NT 6.0)")
            return None

        """ Heap backend structures """
        _HEAP = kernel.get_type("_HEAP")
        _HEAP_ENTRY = kernel.get_type("_HEAP_ENTRY")
        granularity = _HEAP_ENTRY.size

        """
        Front end layer structures, Windows only supports LFH.
        We need to load ntdll.pdb symbols to access the LFH structures
        """
        ntdll = self._load_ntdll_symbols()

        if ntdll is None:
            vollog.warning(f"Failed to load symbols for ntdll.dll, LFH layer parsing is disabled")

        for proc in procs:
            pid = proc.UniqueProcessId
            proc_name = utility.array_to_string(proc.ImageFileName)

            try:
                peb = proc.get_peb()
                heap_pointers = utility.array_of_pointers(
                                    peb.ProcessHeaps.dereference(),
                                    count=peb.NumberOfHeaps,
                                    subtype=_HEAP,
                                    context=self.context,
                                )
            except exceptions.InvalidAddressException:
                vollog.warning(f"{proc_name} ({pid})\t: Unable to read the _PEB")
                continue

            """ Init capstone to analyze possible code ocurrences into heap entries """
            self.init_capstone(proc)

            for heap in heap_pointers:
                try:
                    vollog.debug(f"_HEAP\t\t\t: {heap:#x}")
                    lfh_entries = {}

                    """ We loaded the ntdll.dll symbols to work with the LFH """
                    if ntdll is not None:
                        """ LFH front end layer is active for this _HEAP """
                        if heap.FrontEndHeapType == LFH_HEAP_ACTIVE:
                            try:
                                lfh_entries = self._get_lfh_entries(proc_name, pid, ntdll, peb.vol.layer_name, heap.FrontEndHeap)
                            except exceptions.InvalidAddressException:
                                vollog.warning(f"{proc_name} ({pid})\t: Unable to parse the _LFH_HEAP of _HEAP {heap:#x}")

                    """ Traverse the heap reserved by the backend layer """
                    segments = heap.SegmentList.to_list(f"{kernel.symbol_table_name}{constants.BANG}_HEAP_SEGMENT", "SegmentListEntry")

                    for segment in segments:
                        try:
                            heap_entry_addr = int(segment.FirstEntry)

                            """ Get the uncommitted regions to avoid any reads """
                            uncommitted_regions = []
                            if segment.NumberOfUnCommittedPages:
                                for uncommitted_region in segment.UCRSegmentList.to_list(f"{kernel.symbol_table_name}{constants.BANG}_HEAP_UCR_DESCRIPTOR", "SegmentEntry"):
                                    uncommitted_regions.append((uncommitted_region.Address, uncommitted_region.Size))


                            next_entry_by_size = 0
                            while heap_entry_addr < segment.LastValidEntry:
                                if uncommitted_regions:
                                    no_uncommitted_bytes = self._is_addr_uncommitted(heap_entry_addr, uncommitted_regions)
                                    """ Skip the entire uncommitted region """
                                    if no_uncommitted_bytes:
                                        heap_entry_addr += no_uncommitted_bytes
                                        continue

                                heap_entry = self.context.object(_HEAP_ENTRY, peb.vol.layer_name, heap_entry_addr)

                                heap_entry_size = heap_entry.Size
                                heap_entry_flags = heap_entry.Flags

                                """ The _HEAP_ENTRYs have encoded size and flags, decoded with the values from the _HEAP """
                                if heap.EncodeFlagMask == 0x100000:
                                    heap_entry_size ^= heap.Encoding.Size
                                    heap_entry_flags ^=  heap.Encoding.Flags

                                heap_entry_size *= granularity
                                heap_layer = "backend"

                                (decoded_data, file_output, data) = self._generate_output(proc_name, pid, peb.vol.layer_name, heap_entry, heap_entry_size, granularity)
                                results = [pid,
                                            proc_name,
                                            format_hints.Hex(heap),
                                            format_hints.Hex(segment.BaseAddress),
                                            format_hints.Hex(heap_entry_addr),
                                            format_hints.Hex(heap_entry_size),
                                            f"[{heap_entry_flags:02x}]",
                                            self._flag_to_string(heap_entry_flags),
                                            heap_layer,
                                            decoded_data,
                                            file_output
                                    ]

                                """ Possible attacks dtection based on patterns """          
                                if self.config["detect-attacks"]:            
                                    (detected_attack, attack_details) = self.is_attacked(heap_entry_flags, heap_entry_size, heap_entry_addr, next_entry_by_size, segment.LastValidEntry, data)    
                                    results.append(detected_attack)
                                    results.append(attack_details)

                                next_entry_by_size = heap_entry_addr + heap_entry_size 
                                    
                                """ Show results """
                                yield (0, tuple(results))

                                """
                                If the _HEAP_ENTRY is allocated internally by the LFH heap, we only need to check the _HEAP_ENTRYs
                                that were allocated using VirtualAlloc
                                """
                                if lfh_entries and (HEAP_ENTRY_FLAGS.VIRTUAL_ALLOC in HEAP_ENTRY_FLAGS(heap_entry_flags)):
                                    user_blocks_address = heap_entry_addr + granularity

                                    """ This _HEAP_ENTRY is actually managed by the LFH heap, let's show the entries already collected """
                                    if user_blocks_address in lfh_entries:
                                        heap_layer = "lfh"

                                        lfh_heap_entry_size = lfh_entries[user_blocks_address]["block_stride"]

                                        for lfh_heap_entry in lfh_entries[user_blocks_address]["heap_entries"]:
                                            """ We could not retrieve the _HEAP_ENTRY from memory, we only know the address """
                                            if isinstance(lfh_heap_entry, int):
                                                results = [
                                                        pid,
                                                        proc_name,
                                                        format_hints.Hex(heap),
                                                        format_hints.Hex(segment.BaseAddress),
                                                        format_hints.Hex(lfh_heap_entry),
                                                        format_hints.Hex(0),
                                                        "????",
                                                        "????",
                                                        heap_layer,
                                                        "????",
                                                        "Unavailable",                                                        
                                                    ]
                                                
                                                if self.config["detect-attacks"]: 
                                                    (detected_attack_spray, attack_details_spray) = self.check_spray(data)
                                                    results.append("????")
                                                    results.append("????")

                                                """ Show results """
                                                yield (0, tuple(results))
                                            else:
                                                """ We can obtain the _HEAP_ENTRY status directly from _HEAP_ENTRY.UnusedBytes """
                                                lfh_heap_entry_flags = lfh_heap_entry.UnusedBytes

                                                if lfh_heap_entry_flags > LFH_HEAP_ENTRY_FREE:
                                                    lfh_heap_entry_flags_str = "busy"
                                                elif lfh_heap_entry_flags == LFH_HEAP_ENTRY_FREE:
                                                    lfh_heap_entry_flags_str = "free"
                                                else:
                                                    lfh_heap_entry_flags_str = "????"

                                                (decoded_data, file_output, data) = self._generate_output(proc_name, pid, peb.vol.layer_name, lfh_heap_entry, lfh_heap_entry_size, granularity)

                                                results = [
                                                        pid,
                                                        proc_name,
                                                        format_hints.Hex(heap),
                                                        format_hints.Hex(segment.BaseAddress),
                                                        format_hints.Hex(lfh_heap_entry.vol.offset),
                                                        format_hints.Hex(lfh_heap_entry_size),
                                                        f"[{lfh_heap_entry_flags:02x}]",
                                                        lfh_heap_entry_flags_str,
                                                        heap_layer,
                                                        decoded_data,
                                                        file_output
                                                    ]

                                                """ Overflow is exclusive of backend, LFH is less deterministic """
                                                if self.config["detect-attacks"]: 
                                                    (detected_attack_spray, attack_details_spray) = self.check_spray(data)
                                                    results.append(detected_attack_spray)
                                                    results.append(attack_details_spray)

                                                """ Show results """
                                                yield (0, tuple(results))

                                """ Finally, move the pointer to the next _HEAP_ENTRY """
                                heap_entry_addr = next_entry_by_size 
                        except exceptions.InvalidAddressException:
                            vollog.warning(f"{proc_name} ({pid})\t: _HEAP_ENTRY missing\t: _HEAP {heap:#x}\t: Unable to read the _HEAP_SEGMENT {segment.BaseAddress:#x} beyond _HEAP_ENTRY {heap_entry_addr:#x}")
                except exceptions.InvalidAddressException:
                    vollog.warning(f"{proc_name} ({pid})\t: Unable to access the _HEAP @ {heap:#x}")

    def run(self):
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))

        columns = [
                ("PID", int),
                ("Name", str),
                ("Heap", format_hints.Hex),
                ("Segment", format_hints.Hex),
                ("Entry", format_hints.Hex),
                ("Size", format_hints.Hex),
                ("Flags", str),
                ("State", str),
                ("Layer", str),
                ("Data", str),
                ("File Output", str)
            ]
        
        if self.config["detect-attacks"]:
            columns.append(("Detected Attack", str))
            columns.append(("Attack Details", str))

        return renderers.TreeGrid(
            columns,
            self._generator(
                pslist.PsList.list_processes(
                    context=self.context,
                    kernel_module_name=self.config["kernel"],
                    filter_func=filter_func,
                )
            ),
        )
