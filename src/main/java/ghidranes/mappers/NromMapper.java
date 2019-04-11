package ghidranes.mappers;

import java.util.Arrays;

import ghidra.framework.store.LockException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;
import ghidranes.NesRom;
import ghidranes.util.MemoryBlockDescription;

public class NromMapper extends NesMapper {
	@Override
	public void updateMemoryMapForRom(NesRom rom, Program program, TaskMonitor monitor) throws LockException, MemoryConflictException, AddressOverflowException, CancelledException, DuplicateNameException {
		// TODO: Do we always want to include work RAM?
		int workRamPermissions =
			MemoryBlockDescription.READ | MemoryBlockDescription.WRITE | MemoryBlockDescription.EXECUTE;
		MemoryBlockDescription.uninitialized(0x6000, 0x2000, "WORK_RAM", workRamPermissions, false)
			.create(program);

		// TODO: Do we need all this? It appears no NROM games have anything besides 16K or 32K, so we will only ever need to create one mirror
		for (int romMirror = 0; romMirror * rom.prgRom.length < 0x8000; romMirror++) {
			int romMirrorOffsetStart = romMirror * rom.prgRom.length;
			int romMirrorLength = Math.min(rom.prgRom.length, 0x8000);

			int romMirrorStart = romMirrorOffsetStart + 0x8000;
			int romPermissions =
					MemoryBlockDescription.READ | MemoryBlockDescription.EXECUTE;

			if (romMirror == 0) {
				byte[] romBytes = Arrays.copyOfRange(rom.prgRom, 0, romMirrorLength);
				MemoryBlockDescription.initialized(romMirrorStart, romMirrorLength, "PRG_ROM", romPermissions, romBytes, false, monitor)
					.create(program);
			}
			else {
				MemoryBlockDescription.byteMapped(romMirrorStart, romMirrorLength, "PRG_ROM_MIRROR_" + romMirror, romPermissions, 0x8000)
					.create(program);
			}
		}
	}

}
