package ghidranes.mappers;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

import ghidra.framework.store.LockException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;
import ghidranes.NesRom;
import ghidranes.util.Bank;
import ghidranes.util.MemoryBlockDescription;
import ghidranes.util.NesMmio;

public class MMC3Mapper extends NesMapper {
	@Override
	public void mapPrgRom(NesRom rom, Program program, TaskMonitor monitor) throws LockException, MemoryConflictException, AddressOverflowException, CancelledException, DuplicateNameException {
		/*
		https://www.nesdev.org/wiki/MMC3
		CPU $6000-$7FFF: 8 KB PRG RAM bank (optional)
		CPU $8000-$9FFF (or $C000-$DFFF): 8 KB switchable PRG ROM bank
		CPU $A000-$BFFF: 8 KB switchable PRG ROM bank
		CPU $C000-$DFFF (or $8000-$9FFF): 8 KB PRG ROM bank, fixed to the second-last bank
		CPU $E000-$FFFF: 8 KB PRG ROM bank, fixed to the last bank
		*/
		int sramPermissions =
			MemoryBlockDescription.READ | MemoryBlockDescription.WRITE | MemoryBlockDescription.EXECUTE;
		// CPU $6000-$7FFF: 8 KB PRG RAM bank (optional)
		MemoryBlockDescription.uninitialized(0x6000, 0x2000, "SRAM", sramPermissions, false)
			.create(program);

		int romPermissions = MemoryBlockDescription.READ | MemoryBlockDescription.EXECUTE;

		Map<String, Integer> prgBankAddresses = getPrgBankAddresses();

		for (int bank = 0; bank < prgBankCount; bank++) {
			byte[] rombankBytes = Arrays.copyOfRange(rom.prgRom, bank*0x2000, (bank+1)*0x2000);
			String name = Bank.getPrgBankName(bank, prgBankCount);
			int baseAddress = prgBankAddresses.get(name);
			if (baseAddress == 0) {
				// add a bank for each address
				// last bank is fixed at $E000 so skip that mirror
				// can't skip other fixed bank cuz it might be at $8000 or $C000
				for (int base=0x8000; base < 0xe000; base += 0x2000) {
					String bankName = Bank.getBankName(bank, prgBankCount, base);
					MemoryBlockDescription.initialized(base, 0x2000, bankName, romPermissions, rombankBytes, true, monitor)
						.create(program);
				}
			} else {
				// add a single bank at the base address
				MemoryBlockDescription.initialized(baseAddress, 0x2000, name, romPermissions, rombankBytes, true, monitor)
					.create(program);
			}
		}
	}

	@Override
	public List<NesMmio> getMapperRegisters(AddressSpace addressSpace) {
		// these are the MMC3 registers; other 8k mappers may differ
		List<NesMmio> registers = super.getMapperRegisters(addressSpace);
		registers.add(new NesMmio(addressSpace, 0x8000, "BANK_SELECT"));
		registers.add(new NesMmio(addressSpace, 0x8001, "BANK_DATA"));
		registers.add(new NesMmio(addressSpace, 0xA000, "MIRRORING"));
		registers.add(new NesMmio(addressSpace, 0xA001, "PRG_RAM_PROTECT"));
		registers.add(new NesMmio(addressSpace, 0xC000, "IRQ_LATCH"));
		registers.add(new NesMmio(addressSpace, 0xC001, "IRQ_RELOAD"));
		registers.add(new NesMmio(addressSpace, 0xE000, "IRQ_DISABLE"));
		registers.add(new NesMmio(addressSpace, 0XE001, "IRQ_ENABLE"));
		return registers;
	}
}
