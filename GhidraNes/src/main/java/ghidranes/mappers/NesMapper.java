package ghidranes.mappers;

import ghidra.framework.store.LockException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;
import ghidranes.NesRom;
import ghidranes.errors.UnimplementedNesMapperException;

public abstract class NesMapper {
	public abstract void updateMemoryMapForRom(NesRom rom, Program program, TaskMonitor monitor) throws LockException, MemoryConflictException, AddressOverflowException, CancelledException, DuplicateNameException;

	public static NesMapper getMapper(int mapperNum) throws UnimplementedNesMapperException {
		switch (mapperNum) {
		case 0:
			return new NromMapper();
		default:
			throw new UnimplementedNesMapperException(mapperNum);
		}
	}
}
