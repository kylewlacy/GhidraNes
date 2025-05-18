package ghidranes.mappers;

import java.util.ArrayList;
import java.util.Arrays;

import ghidra.framework.store.LockException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import ghidranes.NesRom;
import ghidranes.errors.UnimplementedNesMapperException;
import ghidranes.util.NesMmio;

public abstract class NesMapper {
	// store actual mapper number so generalized subclasses can differentiate
	// if needed (e.g. mapper registers)
	protected int mapperNum;
	
	protected void setMapper(int mapperNum) {
		this.mapperNum = mapperNum;
	}

	public static NesMapper getMapper(int mapperNum) throws UnimplementedNesMapperException {
		NesMapper mapper;

		switch (mapperNum) {
		case 0:
			mapper = new NromMapper();
			break;
		case 1:
			mapper = new MMC1Mapper();
			break;
		case 2:
			mapper = new UxROMMapper();
			break;
		case 4:
			mapper = new MMC3Mapper();
			break;
		case 7:
			mapper = new AxROMMapper();
			break;
		case 10:
			mapper = new MMC4Mapper();
			break;
		case 19:
			mapper = new Mapper019();
			break;
		default:
			throw new UnimplementedNesMapperException(mapperNum);
		}
		mapper.setMapper(mapperNum);
		return mapper;
	}

	public void apply(NesRom rom, Program program, TaskMonitor monitor) 
		throws LockException, MemoryConflictException, AddressOverflowException,
			 CancelledException, DuplicateNameException, InvalidInputException
	{
		mapRom(rom, program, monitor);
		mapMMIO(program, monitor);
		mapVectors(program, monitor);
	}

	protected abstract void mapRom(NesRom rom, Program program, TaskMonitor monitor) 
		throws LockException, MemoryConflictException, AddressOverflowException,
			 CancelledException, DuplicateNameException;

	protected void mapMMIO(Program program, TaskMonitor monitor)
		throws InvalidInputException 
		/*throws LockException, MemoryConflictException, AddressOverflowException,
			 CancelledException, DuplicateNameException */	{

		AddressSpace addressSpace = program.getAddressFactory().getDefaultAddressSpace();
		SymbolTable symbolTable = program.getSymbolTable();

		ArrayList<NesMmio> registers = getRegisters(addressSpace);
		for (NesMmio register : registers) {
			Symbol s = symbolTable.createLabel(register.address, register.name, SourceType.IMPORTED);
			s.setPinned(true);
		}
	}

	protected ArrayList<NesMmio> getRegisters(AddressSpace addressSpace) {
		// subclasses can override and add to this list
		return new ArrayList<>(Arrays.asList(
				new NesMmio(addressSpace, 0x2000, "PPUCTRL"),
				new NesMmio(addressSpace, 0x2001, "PPUMASK"),
				new NesMmio(addressSpace, 0x2002, "PPUSTATUS"),
				new NesMmio(addressSpace, 0x2003, "OAMADDR"),
				new NesMmio(addressSpace, 0x2004, "OAMDATA"),
				new NesMmio(addressSpace, 0x2005, "PPUSCROLL"),
				new NesMmio(addressSpace, 0x2006, "PPUADDR"),
				new NesMmio(addressSpace, 0x2007, "PPUDATA"),
				new NesMmio(addressSpace, 0x4000, "SQ1_VOL"),
				new NesMmio(addressSpace, 0x4001, "SQ1_SWEEP"),
				new NesMmio(addressSpace, 0x4002, "SQ1_LO"),
				new NesMmio(addressSpace, 0x4003, "SQ1_HI"),
				new NesMmio(addressSpace, 0x4004, "SQ2_VOL"),
				new NesMmio(addressSpace, 0x4005, "SQ2_SWEEP"),
				new NesMmio(addressSpace, 0x4006, "SQ2_LO"),
				new NesMmio(addressSpace, 0x4007, "SQ2_HI"),
				new NesMmio(addressSpace, 0x4008, "TRI_LINEAR"),
				new NesMmio(addressSpace, 0x400a, "TRI_LO"),
				new NesMmio(addressSpace, 0x400b, "TRI_HI"),
				new NesMmio(addressSpace, 0x400c, "NOISE_VOL"),
				new NesMmio(addressSpace, 0x400e, "NOISE_LO"),
				new NesMmio(addressSpace, 0x400f, "NOISE_HI"),
				new NesMmio(addressSpace, 0x4010, "DMC_FREQ"),
				new NesMmio(addressSpace, 0x4011, "DMC_RAW"),
				new NesMmio(addressSpace, 0x4012, "DMC_START"),
				new NesMmio(addressSpace, 0x4013, "DMC_LEN"),
				new NesMmio(addressSpace, 0x4014, "OAMDMA"),
				new NesMmio(addressSpace, 0x4015, "SND_CHN"),
				new NesMmio(addressSpace, 0x4016, "JOY1"),
				new NesMmio(addressSpace, 0x4017, "JOY2")
		));
	}

	protected void mapVectors(Program program, TaskMonitor monitor) 
		throws LockException, MemoryConflictException, AddressOverflowException,
			 CancelledException, DuplicateNameException
	{
		try {
			// RES should have the highest precedence, followed by NMI, followed by IRQ. We set them
			// as primary in reverse order because the last `.setPrimary()` call has precedence
			addVectorEntryPoint(program, "IRQ", 0xFFFE, "irq");
			addVectorEntryPoint(program, "NMI", 0xFFFA, "vblank");
			addVectorEntryPoint(program, "RES", 0xFFFC, "reset");
		} catch (InvalidInputException | AddressOutOfBoundsException | MemoryAccessException e) {
			throw new RuntimeException(e);
		}
	}
	protected void addVectorEntryPoint(Program program, String vectorLabel, long vectorAddress, String targetLabel)
		 throws InvalidInputException, MemoryAccessException {
		// TODO: default address space might not be the right one here.
		// most mappers seem to map the "last" bank to the highest addresses
		// at startup, so should either make that bank the default address space
		// or explicitly reference the correct bank.
		// other banks will have stub routines to swap in the right bank.	
		AddressSpace addressSpace = program.getAddressFactory().getDefaultAddressSpace();
		SymbolTable symbolTable = program.getSymbolTable();
		Memory memory =  program.getMemory();

		// label the vector
		Address vAddress = addressSpace.getAddress(vectorAddress);
		Symbol vSymbol = symbolTable.createLabel(vAddress, vectorLabel, SourceType.IMPORTED);
		vSymbol.setPinned(true);
		vSymbol.setPrimary();
		//symbolTable.addExternalEntryPoint(vAddress);

		// label the target
		byte vecLo = memory.getByte(vAddress);
		byte vecHi = memory.getByte(vAddress.add(1));
		long vec = (Byte.toUnsignedLong(vecHi) << 8) | Byte.toUnsignedLong(vecLo);
		Address vTargetAddress = addressSpace.getAddress(vec);

		Symbol vTargetSymbol = symbolTable.createLabel(vTargetAddress, targetLabel, SourceType.IMPORTED);
		symbolTable.addExternalEntryPoint(vTargetAddress);

		vTargetSymbol.setPrimary();
	}
}
