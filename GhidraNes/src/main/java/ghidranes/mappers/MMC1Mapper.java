package ghidranes.mappers;

import java.util.Arrays;
import java.util.Map;

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

public class MMC1Mapper extends NesMapper {
	@Override
	public void mapPrgRom(NesRom rom, Program program, TaskMonitor monitor) throws LockException, MemoryConflictException, AddressOverflowException, CancelledException, DuplicateNameException {
		int sramPermissions =
			MemoryBlockDescription.READ | MemoryBlockDescription.WRITE | MemoryBlockDescription.EXECUTE;
		MemoryBlockDescription.uninitialized(0x6000, 0x2000, "SRAM", sramPermissions, false)
			.create(program);

		Map<String, Integer> prgBankAddresses = getPrgBankAddresses();
		
		for (int bank = 0; bank < prgBankCount; bank++) {
			int romPermissions = MemoryBlockDescription.READ | MemoryBlockDescription.EXECUTE;

			byte[] rombankBytes = Arrays.copyOfRange(rom.prgRom, bank*0x4000, (bank+1)*0x4000);
			String name = Bank.getPrgBankName(bank, prgBankCount);
			int baseAddress = prgBankAddresses.get(name);
			if (baseAddress == 0) {
				// add a bank for each address
				for (int base=0x8000; base < 0x10000; base += 0x4000) {
					String bankName = Bank.getBankName(bank, prgBankCount, base);
					MemoryBlockDescription.initialized(base, 0x4000, bankName, romPermissions, rombankBytes, true, monitor)
						.create(program);
				}
			} else {
				// add a single bank at the base address
				MemoryBlockDescription.initialized(baseAddress, 0x4000, name, romPermissions, rombankBytes, true, monitor)
					.create(program);
			}
		}
	}

}
