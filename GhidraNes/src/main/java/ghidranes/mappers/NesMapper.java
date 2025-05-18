package ghidranes.mappers;

import java.util.ArrayList;

import ghidra.framework.store.LockException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;
import ghidranes.NesRom;
import ghidranes.util.NesMmio;
import ghidranes.errors.UnimplementedNesMapperException;

public abstract class NesMapper {
	public abstract void updateMemoryMapForRom(NesRom rom, Program program, TaskMonitor monitor) throws LockException, MemoryConflictException, AddressOverflowException, CancelledException, DuplicateNameException;

	public void addExtraRegisters(ArrayList<NesMmio> registers, AddressSpace addressSpace) {
		// Can be overridden to add additional mapper-specific registers
	}

	public static NesMapper getMapper(int mapperNum) throws UnimplementedNesMapperException {
		switch (mapperNum) {
		case 0:
			return new NromMapper();
		case 1,16:
			return new MMC1Mapper();
		case 2:
			return new UxROMMapper();
		case 4:
			return new MMC3Mapper();
		case 7,66:
			return new AxROMMapper();
		case 10:
			return new MMC4Mapper();
		case 19:
			return new Mapper019();
		default:
			throw new UnimplementedNesMapperException(mapperNum);
		}
	}
}
