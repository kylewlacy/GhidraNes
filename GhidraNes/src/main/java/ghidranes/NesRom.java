package ghidranes;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.Option;
import ghidra.framework.store.LockException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import ghidranes.errors.InvalidNesRomHeaderException;
import ghidranes.errors.NesRomEofException;
import ghidranes.errors.UnimplementedNesMapperException;
import ghidranes.mappers.NesMapper;
import ghidranes.util.Bank;
import ghidranes.util.BankAddressOption;
import ghidranes.util.ChrBankOption;
import ghidranes.util.NesMmio;

public class NesRom {
	private static final int TRAINER_SIZE = 512;
	private static final String CHR_BANK_OPTION_NAME = "CHR ROM handling";

	public NesRomHeader header;
	public byte[] trainer;
	public byte[] prgRom;
	public byte[] chrRom;

	private int prgRomSize;
	private int prgBankSize;
	private int prgBankCount;

	private int chrRomSize;
	private List<Integer> chrBankSizes;

	public NesRom(InputStream bytes) 
		throws NesRomEofException, IOException, InvalidNesRomHeaderException, UnimplementedNesMapperException {

		header = new NesRomHeader(bytes);
		if (header.hasTrainer) {
			trainer = bytes.readNBytes(TRAINER_SIZE);
			if (trainer.length < TRAINER_SIZE) {
				throw new NesRomEofException();
			}
		}
		else {
			trainer = null;
		}

		prgRom = bytes.readNBytes(header.prgRomSizeBytes);
		if (prgRom.length < header.prgRomSizeBytes) {
			throw new NesRomEofException();
		}

		chrRom = bytes.readNBytes(header.chrRomSizeBytes);
		if (chrRom.length < header.chrRomSizeBytes) {
			throw new NesRomEofException();
		}
		prgRomSize = header.getPrgRomSizeBytes();
		prgBankSize = NesMapper.getPrgBankSize(header.mapper, prgRomSize);
		prgBankCount = prgRomSize / prgBankSize;
		Msg.info("NesRom", "PRG ROM size: " + prgRomSize + " bytes, " + prgBankCount + " banks of size " + prgBankSize + " bytes");
		chrRomSize = header.getChrRomSizeBytes();
		chrBankSizes = NesMapper.getChrBankSize(header.mapper);
		Msg.info("NesRom", "CHR ROM size: " + chrRomSize + " bytes, possible bank sizes: " + chrBankSizes);
	}

    public List<Option> getLoadOptions() {
		List<Option> list = new ArrayList<>();

		// skip bank options if there is only one bank or bank size is 32k
		// TODO: this might actually belong in the mapper class
		// TODO: use fancy heuristics to guess the right base address for each bank
		if (prgBankCount > 1 && prgBankSize < 0x8000) {
			try {
				for (int i = 0; i < prgBankCount; i++) {
					String bankName = Bank.getPrgBankName(i, prgBankCount);
					int defaultAddress = 0x8000;
					if (i >= prgBankCount - 1) {
						// if this is the last bank, default to the end of the PRG ROM
						defaultAddress = 0x10000 - prgBankSize;
					}
					list.add(new BankAddressOption(bankName, "PRG bank base addresses", prgBankSize, 0x8000, defaultAddress));
				}

			} catch (Exception e) {
				// ignore errors - no extra options in this case
			}
		}

		if (chrRomSize > 0) {
			// add CHR ROM bank options
			list.add(new ChrBankOption(CHR_BANK_OPTION_NAME, chrBankSizes));
		}

		return list;
    }

	public void applyMapper(Program program, TaskMonitor monitor, List<Option> options) 
		throws LockException, MemoryConflictException, AddressOverflowException,
			 CancelledException, DuplicateNameException, InvalidInputException, UnimplementedNesMapperException, InvalidNesRomHeaderException
	{
		NesMapper mapper = NesMapper.getMapper(header.mapper);
		mapper.setPrgBankAddresses(options);
		mapper.setPrgBankCount(prgBankCount);
		mapper.mapPrgRom(this, program, monitor);
		mapper.mapChrRom(this, program, monitor, options);
		mapMMIO(program, monitor, mapper);
		mapper.mapVectors(program, monitor);
	}

	protected void mapMMIO(Program program, TaskMonitor monitor, NesMapper mapper)
		throws InvalidInputException 
		/*throws LockException, MemoryConflictException, AddressOverflowException,
			 CancelledException, DuplicateNameException */	{

		// TODO: mapper MMIO often overlaps PRG ROM - should add a label in
		// each overlay address space so it gets applied consistently
		AddressSpace addressSpace = program.getAddressFactory().getDefaultAddressSpace();
		SymbolTable symbolTable = program.getSymbolTable();

		ArrayList<NesMmio> registers = NesMmio.getDefaultRegisters(addressSpace);
		registers.addAll(mapper.getMapperRegisters(addressSpace));
		for (NesMmio register : registers) {
			Symbol s = symbolTable.createLabel(register.address, register.name, SourceType.IMPORTED);
			s.setPinned(true);
		}
	}

}
