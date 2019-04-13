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

public class UxromMapper extends NesMapper {
	@Override
	public void updateMemoryMapForRom(NesRom rom, Program program, TaskMonitor monitor) throws LockException,
			MemoryConflictException, AddressOverflowException, CancelledException, DuplicateNameException {
		int romPermissions =
			MemoryBlockDescription.READ | MemoryBlockDescription.EXECUTE;

		int numBanks = rom.prgRom.length / 16_384;
		for (int bank = 0; bank < numBanks; bank++) {
			int bankStart = bank * 16_384;
			int bankEnd = Math.min((bank + 1) * 16_384, rom.prgRom.length);
			int bankLength = bankEnd - bankStart;
			byte[] bankData = Arrays.copyOfRange(rom.prgRom, bankStart, bankEnd);

			boolean overlay = bank != 0;
			MemoryBlockDescription.initialized(0x8000, bankLength, "PRG_ROM_BANK_0_" + bank, romPermissions, bankData, overlay, monitor)
				.create(program);
		}

		int lastBankStart = Math.max(0, rom.prgRom.length - 16_384);
		int lastBankEnd = rom.prgRom.length;
		int lastBankLength = lastBankEnd - lastBankStart;
		byte[] lastBankData = Arrays.copyOfRange(rom.prgRom, lastBankStart, lastBankEnd);
		MemoryBlockDescription.initialized(0xC000, lastBankLength, "PRG_ROM_BANK_1_FIXED", romPermissions, lastBankData, false, monitor)
			.create(program);
	}
}
