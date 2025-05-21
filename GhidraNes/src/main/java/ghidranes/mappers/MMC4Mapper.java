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


public class MMC4Mapper extends NesMapper {
	@Override
	public void mapRom(NesRom rom, Program program, TaskMonitor monitor) throws LockException, MemoryConflictException, AddressOverflowException, CancelledException, DuplicateNameException {
		int sramPermissions = MemoryBlockDescription.READ | MemoryBlockDescription.WRITE | MemoryBlockDescription.EXECUTE;
		MemoryBlockDescription.uninitialized(0x6000, 0x2000, "SRAM", sramPermissions, false).create(program);

		int romPermissions = MemoryBlockDescription.READ | MemoryBlockDescription.EXECUTE;
		for (int bank = 0; bank * 0x4000 < rom.prgRom.length; bank++) {
			byte[] rombankBytes = Arrays.copyOfRange(rom.prgRom, bank * 0x4000, (bank + 1) * 0x4000);
			MemoryBlockDescription.initialized(0x8000, 0x4000, "PRG" + bank, romPermissions, rombankBytes, bank != 0, monitor).create(program);
		}

		int lastBank = rom.prgRom.length / 0x4000 - 1;
		byte[] lastBankBytes = Arrays.copyOfRange(rom.prgRom, lastBank * 0x4000, (lastBank + 1) * 0x4000);
		MemoryBlockDescription.initialized(0xC000, 0x4000, "PRG" + lastBank + "_MIRROR", romPermissions, lastBankBytes, false, monitor).create(program);
	}
}
