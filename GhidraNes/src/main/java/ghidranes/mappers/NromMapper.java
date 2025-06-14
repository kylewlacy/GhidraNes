package ghidranes.mappers;

import java.util.Arrays;

import ghidra.framework.store.LockException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;
import ghidranes.NesRom;
import ghidranes.util.Bank;
import ghidranes.util.MemoryBlockDescription;

public class NromMapper extends NesMapper {
	@Override
	public void mapPrgRom(NesRom rom, Program program, TaskMonitor monitor) throws LockException, MemoryConflictException, AddressOverflowException, CancelledException, DuplicateNameException {
		// TODO: Do we always want to include work RAM?
		int sramPermissions =
			MemoryBlockDescription.READ | MemoryBlockDescription.WRITE | MemoryBlockDescription.EXECUTE;
		MemoryBlockDescription.uninitialized(0x6000, 0x2000, "SRAM", sramPermissions, false)
			.create(program);

		int prgRomSize = rom.prgRom.length;
		if (prgRomSize > 0x8000) {
			Msg.warn("NromMapper", "PRG ROM size is larger than 32k, truncating to 32k");
			prgRomSize = 0x8000;
		}

		// how many mirrors should we make?
		// common case is 1 (for 32k PRG ROM) or 2 (for 16k PRG ROM)
		int bankCount = 0x8000 / prgRomSize;
		String basename = Bank.getPrgBankName(0,2);
		byte[] rombankBytes;

		if (bankCount > 1) {
			// 16k * 2 banks
			rombankBytes = Arrays.copyOfRange(rom.prgRom, 0, 0x4000);
			// map first bank at 0xc000 (since vectors need to be at 0xfffx, consider this "primary")
			makeNromPrgBank(program, basename, 0xc000, rombankBytes, monitor);
			// map mirror bank at 0x8000
			makeNromPrgBank(program, basename + "_MIRROR", 0x8000, rombankBytes, monitor);
		} else {
			// 32k * 1 bank
			rombankBytes = Arrays.copyOfRange(rom.prgRom, 0, 0x8000);
			// map single bank at 0x8000
			makeNromPrgBank(program, basename, 0x8000, rombankBytes, monitor);
		}
	}

	protected void makeNromPrgBank(Program program, String name, int baseAddress, byte[] rombankBytes, TaskMonitor monitor)
		 throws LockException, MemoryConflictException, AddressOverflowException, CancelledException, DuplicateNameException {
		int romPermissions = MemoryBlockDescription.READ | MemoryBlockDescription.EXECUTE;

		MemoryBlockDescription.initialized(baseAddress, rombankBytes.length, name, romPermissions, rombankBytes, true, monitor)
			.create(program);
		Msg.info("NromMapper", "Mapped PRG bank: " + name + " at " + String.format("%04x", baseAddress));
	}
}
