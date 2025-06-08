package ghidranes.mappers;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import ghidra.app.util.Option;
import ghidra.framework.store.LockException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import ghidranes.NesRom;
import ghidranes.errors.InvalidNesRomHeaderException;
import ghidranes.errors.UnimplementedNesMapperException;
import ghidranes.util.Bank;
import ghidranes.util.BankAddressOption;
import ghidranes.util.ChrBankOption;
import ghidranes.util.MemoryBlockDescription;
import ghidranes.util.NesMmio;

public abstract class NesMapper {
	// store actual mapper number so generalized subclasses can differentiate
	// if needed (e.g. mapper registers)
	protected int mapperNum;

	protected int prgBankCount;

	protected Map<String, Integer> prgBankAddresses;

	public Map<String, Integer> getPrgBankAddresses() {
		return prgBankAddresses;
	}

	public void setPrgBankAddresses(List<Option> options) throws UnimplementedNesMapperException {
		prgBankAddresses = new java.util.HashMap<>();

		//Msg.info("NesRom", "Setting PRG bank addresses with bank size " + String.format("%04x", prgBankSize));
		for (Option option : options) {
			if (option instanceof BankAddressOption) {
				BankAddressOption bankOption = (BankAddressOption) option;
				String value = (String)bankOption.getValue();
				//Msg.info("NesRom", "Found bank option: " + bankOption.getName() + " with value " + value);
				if (value.equals("All")) {
					prgBankAddresses.put(bankOption.getName(), 0);
				} else {
					prgBankAddresses.put(bankOption.getName(), Integer.parseInt(value, 16));
				}
			}
		}
	}
	
	public void setPrgBankCount(int prgBankCount) {
		Msg.info("NesMapper", "Setting PRG bank count: " + prgBankCount);
		this.prgBankCount = prgBankCount;
	}

	public void setMapper(int mapperNum) {
		this.mapperNum = mapperNum;
	}

	public static NesMapper getMapper(int mapperNum) throws UnimplementedNesMapperException {
		// Mappers are grouped by where, not how, they map PRG ROM.
		// So even though MMC3 and VRC2 may use different registers to
		// bank switch, because they organize them as 8K blocks, we
		// can treat them the same here.

		NesMapper mapper;
		switch (mapperNum) {
			// 16K or 32K fixed PRG ROM
		case 0:   	// NROM
		case 3:   	// CNROM
		case 13:	// CPROM
		case 185:
			mapper = new NromMapper();
			break;

			// 16K bankable PRG ROM
		case 1:		// MMC1 - SxROM
		case 2:		// UxROM
		case 10:	// MMC4 - FxROM
		case 16,30,67,68:
			mapper = new MMC1Mapper();
			break;
		
			// 32K bankable PRG ROM
		case 7:   	// AxROM
		case 11:	//  ColorDreams
		case 34:	// BNROM, NINA-001
		case 38:
		case 66:  	// GxROM
		case 140:
			mapper = new AxROMMapper();
			break;

			// 8K bankable PRG ROM
		case 4:		// MMC3 - TxROM
		case 18:	// Jaleco SS 88006
		case 19:	// Namco 163
		case 21,22,23,25:	// Konami VRC2/4
		case 64:	// RAMBO-1
		case 65:
		case 69:	// Sunsoft FME-7/5B
		case 74:
		case 76:	// Namco 109 variant
		case 88,95:
		case 118:	// MMC3 - TxSROM
		case 119:	// MMC3 - TQROM
		case 154,158,191,192,194,195:
		case 206:	// DxROM
		case 207:
			mapper = new MMC3Mapper();
			break;

			// 8K/16K bankable PRG ROM
		//case 24,26:	// Konami VRC6
		//	mapper = new VRC6Mapper();
		//	break;
		
			// 8K, 16K, or 8K/16K bankable PRG ROM
		//case 5:	// MMC5 - ExROM
		//	mapper = new MMC5Mapper();
		

		default:
			throw new UnimplementedNesMapperException(mapperNum);
		}
		mapper.setMapper(mapperNum);
		Msg.info("NesMapper", "Created mapper: " + mapper.getClass().getSimpleName() + " for mapper number: " + mapperNum);
		return mapper;
	}

	public abstract void mapPrgRom(NesRom rom, Program program, TaskMonitor monitor)
			/*throws InvalidInputException */
		throws LockException, MemoryConflictException, AddressOverflowException,
			 CancelledException, DuplicateNameException;


    public void mapChrRom(NesRom rom, Program program, TaskMonitor monitor, List<Option> options)
		throws LockException, MemoryConflictException, AddressOverflowException,
			 CancelledException, DuplicateNameException {
		// the ChrBankOption should only be present if CHR ROM exists
		for (Option option : options) {
			if (option instanceof ChrBankOption) {
				int blockSize = (int)option.getValue();

				switch (blockSize) {
				case ChrBankOption.SKIP:
					Msg.info("NesMapper", "Skipping CHR ROM mapping");
					break;
				case ChrBankOption.ONE:
					Msg.info("NesMapper", "Mapping CHR ROM as single bank");
					mapChrRomBlock(rom, program, monitor, "CHR_ROM", 0, rom.chrRom.length);
					break;
				default:
					int blockCount = rom.chrRom.length / blockSize;
					Msg.info("NesMapper", "Mapping CHR ROM as " + blockCount + " banks of  " + blockSize/1024 + "K");
					for (int block=0; block < blockCount; block++) {
						mapChrRomBlock(rom, program, monitor, Bank.getChrBankName(block, blockCount), block * blockSize, blockSize);
					}
					break;
				}
			}
		}
	}

	protected void mapChrRomBlock(NesRom rom, Program program, TaskMonitor monitor, String name, int blockStart, int blockSize)
			throws LockException, MemoryConflictException, AddressOverflowException, CancelledException, DuplicateNameException {
		int romPermissions = MemoryBlockDescription.READ | MemoryBlockDescription.EXECUTE;

		if (blockSize > 0x10000) {
			blockSize = 0x10000; // limit to 64K as memory blocks need to fit in 6502 address space
			Msg.warn("NesMapper", "CHR ROM block size " + blockSize + " exceeds 64K, limiting to 64K");
			// TODO: CHR ROM should not live in CPU space anyway
		}

		byte[] chrBankBytes = Arrays.copyOfRange(rom.chrRom, blockStart, blockStart + blockSize);
		MemoryBlockDescription.initialized(0x0000, blockSize, name, romPermissions, chrBankBytes, true, monitor)
			.create(program);
		//Msg.info("NesMapper", "Mapped CHR ROM block: " + name + " with size " + String.format("%04x", blockSize));
	}

	public void mapVectors(Program program, TaskMonitor monitor) 
		throws LockException, MemoryConflictException, AddressOverflowException,
			 CancelledException, DuplicateNameException, InvalidNesRomHeaderException
	{
		try {
			// RES should have the highest precedence, followed by NMI, followed by IRQ. We set them
			// as primary in reverse order because the last `.setPrimary()` call has precedence
			addVectorEntryPoint(program, "IRQ", "FFFE", "irq");
			addVectorEntryPoint(program, "NMI", "FFFA", "vblank");
			addVectorEntryPoint(program, "RES", "FFFC", "reset");
		} catch (InvalidInputException | AddressOutOfBoundsException | MemoryAccessException e) {
			throw new RuntimeException(e);
		}
	}
	protected void addVectorEntryPoint(Program program, String vectorLabel, String vectorAddress, String targetLabel)
		 throws InvalidInputException, MemoryAccessException, InvalidNesRomHeaderException {
		// most mappers seem to map the "last" bank to the highest addresses
		// at startup, so should either make that bank the default address space
		// or explicitly reference the correct bank.
		// other banks will have stub routines to swap in the right bank.
		AddressFactory addressFactory = program.getAddressFactory();	
		SymbolTable symbolTable = program.getSymbolTable();
		Memory memory =  program.getMemory();

		// label the vector
		Address vAddress = null;
		try {
			String fullAddress = getLastBankName() + "::" + vectorAddress;
			vAddress = addressFactory.getAddress(fullAddress);
			Msg.info("NesMapper", "Vector: " + vectorLabel + " addr " + fullAddress + " factory returned address: " + vAddress);
			Msg.info("NesMapper", "Vector: " + vectorLabel + " all addrs: " + Arrays.toString(addressFactory.getAllAddresses(vectorAddress)));
		} catch (UnimplementedNesMapperException e) {
			// huh wat
			Msg.error("NesMapper", "got unexcepted mapper");
			throw new MemoryAccessException();
		}
		Msg.info("NesMapper", "Vector: " + vectorLabel + " factory returned address: " + vAddress);
		Symbol vSymbol = symbolTable.createLabel(vAddress, vectorLabel, SourceType.IMPORTED);
		vSymbol.setPinned(true);
		vSymbol.setPrimary();

		// TODO: label the target; need to get the address space setup right first
		try {
			short vec = memory.getShort(vAddress);
			Msg.info("NesMapper", "Vector: " + vectorLabel + " value: " + String.format("%04x", vec));
			Address vTargetAddress = addressFactory.getAddress(String.format("%s::%04x", getLastBankName(), vec));
			Msg.info("NesMapper", "Vector: " + vectorLabel + " value address: " + vTargetAddress);

			Symbol vTargetSymbol = symbolTable.createLabel(vTargetAddress, targetLabel, SourceType.IMPORTED);
			symbolTable.addExternalEntryPoint(vTargetAddress);

			vTargetSymbol.setPrimary();
			try {
				program.getListing().createData(vAddress, new PointerDataType());
			} catch (CodeUnitInsertionException e) {
				Msg.error("NesMapper", "Error creating data at vector address " + vAddress + ": " + e.getMessage());
			}
		} catch (MemoryAccessException | AddressOutOfBoundsException | UnimplementedNesMapperException e) {
			Msg.error(this, "IGNORING: Error reading vector address " + vectorAddress + ": " + e.getMessage());
			// keep on truckin'
		}
	}

    public List<NesMmio> getMapperRegisters(AddressSpace addressSpace) {
		// default: nothing; subclasses can override to add mapper-specific registers

		return new ArrayList<NesMmio>();
    }

	private String getLastBankName() throws UnimplementedNesMapperException, InvalidNesRomHeaderException {
		int lastBank = prgBankCount - 1;
		if (lastBank < 0) {
			throw new InvalidNesRomHeaderException("PRG bank count is less than 1: " + prgBankCount); 
		}
		String bankName = Bank.getPrgBankName(lastBank, prgBankCount);
		Msg.info("NesMapper", "Last bank name: " + bankName + " prgBankCount: " + prgBankCount);
		if (prgBankAddresses.containsKey(bankName)) {
			int baseAddress = prgBankAddresses.get(bankName);
			Msg.info("NesMapper", "Last bank base address: " + String.format("%04x", baseAddress));
			if (baseAddress == 0) {
				// special case: "All" banks
				int prgBankSize = getPrgBankSize(mapperNum, prgBankCount);
				int lastBankAddress = 0x10000 - prgBankSize;
				bankName = Bank.getBankName(prgBankCount, prgBankCount, lastBankAddress);
			}
		}
		Msg.info("NesMapper", "Returning last bank name: " + bankName);
		return bankName;	
	}

	public static int getPrgBankSize(int mapperNum, int prgRomSize) throws UnimplementedNesMapperException {
		// TODO: this should probably be moved into the specific mapper classes
		switch (mapperNum) {
			// 16K or 32K fixed PRG ROM
		case 0:   	// NROM
		case 3:   	// CNROM
		case 13:	// CPROM
			return prgRomSize; // bank size == rom size

			// 16K bankable PRG ROM
		case 1:		// MMC1 - SxROM  - could possibly be 32K banks
		case 2:		// UxROM
		case 10:	// MMC4 - FxROM
		case 16,30,67,68:
			return 0x4000; // 16K banks
		
			// 32K bankable PRG ROM
		case 7:   	// AxROM
		case 11:	//  ColorDreams
		case 34:	// BNROM, NINA-001
		case 38:
		case 66:  	// GxROM
		case 140:
			return 0x8000; // 32K banks

			// 8K bankable PRG ROM
		case 4:		// MMC3 - TxROM
		case 18:	// Jaleco SS 88006
		case 19:	// Namco 163
		case 21,22,23,25:	// Konami VRC2/4
		case 64:	// RAMBO-1
		case 65:
		case 69:	// Sunsoft FME-7/5B
		case 74:
		case 76:	// Namco 109 variant
		case 88,95:
		case 118:	// MMC3 - TxSROM
		case 119:	// MMC3 - TQROM
		case 154,158,191,192,194,195:
		case 206:	// DxROM
		case 207:
			return 0x2000; // 8K banks

			// 8K/16K bankable PRG ROM
		//case 24,26:	// Konami VRC6
		//	return new VRC6Mapper();
		
			// 8K, 16K, or 8K/16K bankable PRG ROM
		//case 5:	// MMC5 - ExROM
		//	return new MMC5Mapper();

		default:
			throw new UnimplementedNesMapperException(mapperNum);
		}
	}

	public static List<Integer> getChrBankSize(int mapperNum) {
		// TODO: this should probably be moved into the specific mapper classes
		List<Integer> sizes = new ArrayList<Integer>();
		switch (mapperNum) {
			// Supports 8K CHR ROM banks
		case 0:   	// NROM
		case 1:		// MMC1 - SxROM
		case 2:		// UxROM
		case 3:   	// CNROM
		//case 5:	// MMC5 - ExROM
		case 7:   	// AxROM
		case 11:	//  ColorDreams
		case 13:	// CPROM
		case 34:	// BNROM, NINA-001
		case 66:  	// GxROM
		case 16,30,38,67,68,140:
			sizes.add(0x2000);
		}

		switch (mapperNum) {
			// Supports 4K CHR ROM banks
		case 1:		// MMC1 - SxROM
		//case 5:	// MMC5 - ExROM
		case 10:	// MMC4 - FxROM
			sizes.add(0x1000);
		}

		switch (mapperNum) {
			// Supports 2K CHR ROM banks
		case 4:		// MMC3 - TxROM
		//case 5:	// MMC5 - ExROM
		case 64:	// RAMBO-1
		case 76:	// Namco 109 variant
		case 118:	// MMC3 - TxSROM
		case 119:	// MMC3 - TQROM
		case 206:	// DxROM
		case 74,88,95,154,191,192,194,195,207:
			sizes.add(0x800);
		}

		switch (mapperNum) {
			// Supports 1K CHR ROM banks
		case 4:		// MMC3 - TxROM
		//case 5:	// MMC5 - ExROM
		case 18:	// Jaleco SS 88006
		case 19:	// Namco 163
		case 21,22,23,25:	// Konami VRC2/4
		//case 24,26:	// Konami VRC6
		case 64:	// RAMBO-1
		case 69:	// Sunsoft FME-7/5B
		case 118:	// MMC3 - TxSROM
		case 119:	// MMC3 - TQROM
		case 206:	// DxROM
		case 65,74,88,95,154,191,192,194,195,207:
		    sizes.add(0x400);
		}
		
		if (sizes.isEmpty()) {
			Msg.warn("NesMapper", "No CHR bank sizes found for mapper " + mapperNum + ", returning empty list");
		}
		return sizes;
	}
}
