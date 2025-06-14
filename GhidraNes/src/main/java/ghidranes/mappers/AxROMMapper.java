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
import ghidranes.util.Bank;
import ghidranes.util.MemoryBlockDescription;

public class AxROMMapper extends NesMapper {
	@Override
	public void mapPrgRom(NesRom rom, Program program, TaskMonitor monitor) throws LockException, MemoryConflictException, AddressOverflowException, CancelledException, DuplicateNameException {
		if (rom.header.getHasPersistence() || (rom.header.getPrgRamSizeBytes() > 0)) {
			// AxROM normally doesn't have PRG RAM but allocate if header says so
			int sramPermissions =
				MemoryBlockDescription.READ | MemoryBlockDescription.WRITE | MemoryBlockDescription.EXECUTE;
			MemoryBlockDescription.uninitialized(0x6000, 0x2000, "SRAM", sramPermissions, false)
				.create(program);
		}

		int romPermissions = MemoryBlockDescription.READ | MemoryBlockDescription.EXECUTE;

		/* AxROM contains 32k selectable PRG ROM banks mapped to 8000-FFFF. */
		int bankCount = rom.prgRom.length / 0x8000;

		for (int bank = 0; bank < bankCount; bank++) {
			String bankName = Bank.getPrgBankName(bank, bankCount);
			byte[] rombankBytes = Arrays.copyOfRange(rom.prgRom, bank*0x8000, (bank+1)*0x8000);
			MemoryBlockDescription.initialized(0x8000, 0x8000, bankName, romPermissions, rombankBytes, true, monitor)
				.create(program);
		}
	}

}
