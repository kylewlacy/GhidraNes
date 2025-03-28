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

public class MMC3Mapper extends NesMapper {
	@Override
	public void updateMemoryMapForRom(NesRom rom, Program program, TaskMonitor monitor) throws LockException, MemoryConflictException, AddressOverflowException, CancelledException, DuplicateNameException {
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
		
		// Leave 2 banks free for fixed banks
		int bank = 0;
		for (bank = 0; (bank + 2) * 0x2000 < rom.prgRom.length; bank++) {
			int romPermissions = MemoryBlockDescription.READ | MemoryBlockDescription.EXECUTE;

			byte[] rombankBytes = Arrays.copyOfRange(rom.prgRom, bank*0x2000, (bank+1)*0x2000);
			//CPU $8000-$9FFF (or $C000-$DFFF): 8 KB switchable PRG ROM bank
			//CPU $A000-$BFFF: 8 KB switchable PRG ROM bank
			MemoryBlockDescription.initialized(0x8000, 0x2000, "PRG" + bank, romPermissions, rombankBytes, bank != 0, monitor)
				.create(program);
			MemoryBlockDescription.initialized(0xA000, 0x2000, "PRG" + bank + "_MIRROR1", romPermissions, rombankBytes, bank != 0, monitor)
				.create(program);
			MemoryBlockDescription.initialized(0xC000, 0x2000, "PRG" + bank + "_MIRROR2", romPermissions, rombankBytes, bank != 0, monitor)
				.create(program);
		}
		
		// Final 2 fixed banks
		int romPermissions = MemoryBlockDescription.READ | MemoryBlockDescription.EXECUTE;
		byte[] rombankBytes = Arrays.copyOfRange(rom.prgRom, bank*0x2000, (bank+1)*0x2000);
		//CPU $C000-$DFFF (or $8000-$9FFF): 8 KB PRG ROM bank, fixed to the second-last bank
		MemoryBlockDescription.initialized(0x8000, 0x2000, "PRG" + bank + "_FIXED1", romPermissions, rombankBytes, true, monitor)
			.create(program);
		MemoryBlockDescription.initialized(0xC000, 0x2000, "PRG" + bank + "_FIXED1_MIRROR", romPermissions, rombankBytes, true, monitor)
			.create(program);
		
		bank += 1;
		rombankBytes = Arrays.copyOfRange(rom.prgRom, bank*0x2000, (bank+1)*0x2000);
		//CPU $E000-$FFFF: 8 KB PRG ROM bank, fixed to the last bank
		MemoryBlockDescription.initialized(0xE000, 0x2000, "PRG" + bank + "_FIXED2", romPermissions, rombankBytes, false, monitor)
			.create(program);
	}

}
