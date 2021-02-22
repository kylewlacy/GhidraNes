package ghidranes.util;

import java.io.ByteArrayInputStream;
import java.io.InputStream;

import ghidra.framework.store.LockException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

public class MemoryBlockDescription {
	public static int READ = 1 << 0;
	public static int WRITE = 1 << 1;
	public static int EXECUTE = 1 << 2;
	public static int VOLATILE = 1 << 3;
	
	long start;
	long length;
	String name;
	MemoryBlockType type;
	int permissions;
	byte[] data;
	long mappedTo;
	boolean overlay;
	TaskMonitor monitor;
	
	MemoryBlockDescription() {
		
	}

	public void create(Memory memory, AddressSpace addressSpace) throws LockException, MemoryConflictException, AddressOverflowException, CancelledException, DuplicateNameException {
		Address startAddress = addressSpace.getAddress(start);
		InputStream dataStream = new ByteArrayInputStream(data);
		
		Address mappedAddress;
		
		switch(type) {
		case INITIALIZED:
			memory.createInitializedBlock(name, startAddress, dataStream, length, monitor, overlay);
			break;
		case UNINITIALIZED:
			memory.createUninitializedBlock(name, startAddress, length, overlay);
			break;
		case BIT_MAPPED:
			mappedAddress = addressSpace.getAddress(mappedTo);
			memory.createBitMappedBlock(name, startAddress, mappedAddress, length, overlay);
			break;
		case BYTE_MAPPED:
			mappedAddress = addressSpace.getAddress(mappedTo);
			memory.createByteMappedBlock(name, startAddress, mappedAddress, length, overlay);
			break;
		}
		
		MemoryBlock block = memory.getBlock(name);
		block.setRead((permissions & READ) != 0);
		block.setWrite((permissions & WRITE) != 0);
		block.setExecute((permissions & EXECUTE) != 0);
		block.setVolatile((permissions & VOLATILE) != 0);
	}
	
	public void create(Program program) throws LockException, MemoryConflictException, AddressOverflowException, CancelledException, DuplicateNameException {
		create(program.getMemory(), program.getAddressFactory().getDefaultAddressSpace());
	}
	
	public static MemoryBlockDescription initialized(
		long start,
		long length,
		String name,
		int permissions,
		byte[] data,
		boolean overlay,
		TaskMonitor monitor
	) {
		MemoryBlockDescription block = new MemoryBlockDescription();
		block.start = start;
		block.length = length;
		block.name = name;
		block.permissions = permissions;
		block.type = MemoryBlockType.INITIALIZED;
		block.data = data;
		block.overlay = overlay;
		block.monitor = monitor;
		
		return block;
	}
	
	public static MemoryBlockDescription uninitialized(
		long start,
		long length,
		String name,
		int permissions,
		boolean overlay
	) {
		MemoryBlockDescription block = new MemoryBlockDescription();
		block.start = start;
		block.length = length;
		block.name = name;
		block.permissions = permissions;
		block.type = MemoryBlockType.UNINITIALIZED;
		block.data = new byte[0];
		block.overlay = overlay;
		
		return block;
	}
	
	public static MemoryBlockDescription bitMapped(
		long start,
		long length,
		String name,
		int permissions,
		long mappedTo
	) {
		MemoryBlockDescription block = new MemoryBlockDescription();
		block.start = start;
		block.length = length;
		block.name = name;
		block.permissions = permissions;
		block.type = MemoryBlockType.BIT_MAPPED;
		block.data = new byte[0];
		block.mappedTo = mappedTo;
		block.overlay = false;
		
		return block;
	}
	
	public static MemoryBlockDescription byteMapped(
		long start,
		long length,
		String name,
		int permissions,
		long mappedTo
	) {
		MemoryBlockDescription block = new MemoryBlockDescription();
		block.start = start;
		block.length = length;
		block.name = name;
		block.permissions = permissions;
		block.type = MemoryBlockType.BYTE_MAPPED;
		block.data = new byte[0];
		block.mappedTo = mappedTo;
		block.overlay = false;
		
		return block;
	}
}
