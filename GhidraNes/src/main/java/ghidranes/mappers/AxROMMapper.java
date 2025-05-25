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

public class AxROMMapper extends NesMapper {
	@Override
	public void mapRom(NesRom rom, Program program, TaskMonitor monitor) throws LockException, MemoryConflictException, AddressOverflowException, CancelledException, DuplicateNameException {

		/* AxROM contains 32k selectable PRG ROM banks mapped to 8000-FFFF.
		   Assumes last bank is active at initial startup (so no overlay flag). */
		int bankCount = rom.prgRom.length / 0x8000;

		for (int bank = 0; bank < bankCount; bank++) {
			int romPermissions = MemoryBlockDescription.READ | MemoryBlockDescription.EXECUTE;

			byte[] rombankBytes = Arrays.copyOfRange(rom.prgRom, bank*0x8000, (bank+1)*0x8000);
			MemoryBlockDescription.initialized(0x8000, 0x8000, "PRG" + bank, romPermissions, rombankBytes, bank < (bankCount - 1), monitor)
				.create(program);
		}
	}

}
