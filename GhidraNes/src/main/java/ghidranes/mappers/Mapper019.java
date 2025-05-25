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

// TODO: Mapper 019 has some writable registers mapped at 0x8000-0xFFFF,
// which aren't currently handled

public class Mapper019 extends NesMapper {
	@Override
	public void mapRom(NesRom rom, Program program, TaskMonitor monitor) throws LockException, MemoryConflictException, AddressOverflowException, CancelledException, DuplicateNameException {
		int sramPermissions =
			MemoryBlockDescription.READ | MemoryBlockDescription.WRITE | MemoryBlockDescription.EXECUTE;
		MemoryBlockDescription.uninitialized(0x6000, 0x2000, "SRAM", sramPermissions, false)
			.create(program);

		int bank = 0;
		for (bank = 0; (bank + 1) * 0x2000 < rom.prgRom.length; bank++) {
			int romPermissions = MemoryBlockDescription.READ | MemoryBlockDescription.EXECUTE;

			byte[] rombankBytes = Arrays.copyOfRange(rom.prgRom, bank*0x2000, (bank+1)*0x2000);

			MemoryBlockDescription.initialized(0x8000, 0x2000, "PRG" + bank, romPermissions, rombankBytes, bank != 0, monitor)
				.create(program);
			MemoryBlockDescription.initialized(0xA000, 0x2000, "PRG" + bank + "_MIRROR1", romPermissions, rombankBytes, bank != 0, monitor)
				.create(program);
			MemoryBlockDescription.initialized(0xC000, 0x2000, "PRG" + bank + "_MIRROR2", romPermissions, rombankBytes, bank != 0, monitor)
				.create(program);
		}

		// E000-FFFF is fixed at the last bank
		int romPermissions = MemoryBlockDescription.READ | MemoryBlockDescription.EXECUTE;
		byte[] rombankBytes = Arrays.copyOfRange(rom.prgRom, bank*0x2000, (bank+1)*0x2000);
		MemoryBlockDescription.initialized(0xE000, 0x2000, "PRG" + bank + "_FIXED", romPermissions, rombankBytes, false, monitor)
			.create(program);
	}

}
