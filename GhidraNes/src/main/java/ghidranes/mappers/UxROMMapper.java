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

public class UxROMMapper extends NesMapper {
    @Override
    public void mapRom(NesRom rom, Program program, TaskMonitor monitor) throws LockException, MemoryConflictException, AddressOverflowException, CancelledException, DuplicateNameException {

        /* UxROM has switchable 16k PRG ROM banks mapped at 8000-FFFF.
           The lower bank (fixed at 8000-BFFF) is typically the first bank, and 
           the upper bank (C000-FFFF) is switchable. */
        int bankCount = rom.prgRom.length / 0x4000;

        // Load the fixed lower bank (first 16KB)
        int lowerBankPermissions = MemoryBlockDescription.READ | MemoryBlockDescription.EXECUTE;
        byte[] lowerBankBytes = Arrays.copyOfRange(rom.prgRom, 0, 0x4000);
        MemoryBlockDescription.initialized(0x8000, 0x4000, "PRG Lower", lowerBankPermissions, lowerBankBytes, false, monitor)
            .create(program);

        // Load switchable upper banks
        for (int bank = 1; bank < bankCount; bank++) {
            int upperBankPermissions = MemoryBlockDescription.READ | MemoryBlockDescription.EXECUTE;

            byte[] upperBankBytes = Arrays.copyOfRange(rom.prgRom, bank*0x4000, (bank+1)*0x4000);
            MemoryBlockDescription.initialized(0xC000, 0x4000, "PRG Upper " + bank, upperBankPermissions, upperBankBytes, bank < (bankCount - 1), monitor)
                .create(program);
        }
    }
}
