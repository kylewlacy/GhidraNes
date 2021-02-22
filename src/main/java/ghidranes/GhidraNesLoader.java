/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidranes;

import ghidra.program.model.mem.MemoryBlock;
import static ghidranes.util.AddressSpaceUtil.getLittleEndianAddress;
import java.io.IOException;
import java.io.InputStream;
import java.util.*;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.framework.store.LockException;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.address.Address;
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
import ghidranes.errors.NesRomException;
import ghidranes.errors.UnimplementedNesMapperException;
import ghidranes.mappers.NesMapper;
import ghidranes.util.MemoryBlockDescription;

/**
 * TODO: Provide class-level documentation that describes what this loader does.
 */
public class GhidraNesLoader extends AbstractLibrarySupportLoader {

	@Override
	public String getName() {
		return "NES ROM";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		InputStream bytes = provider.getInputStream(0);

		try {
			// Try to parse the ROM header (will throw an exception if parsing fails)
			new NesRomHeader(bytes);

			// If successful, add the load spec
			LanguageCompilerSpecPair languageCompilerSpecPair = new LanguageCompilerSpecPair("6502:LE:16:default", "default");
			LoadSpec loadSpec = new LoadSpec(this, 0, languageCompilerSpecPair, true);
			loadSpecs.add(loadSpec);
		}
		catch (NesRomException e) {
			// If parsing failed, do not add the load spec
		}

		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {
		InputStream bytes = provider.getInputStream(0);

		NesRom rom;
		try {
			NesRomHeader header = new NesRomHeader(bytes);
			rom = new NesRom(header, bytes);
		} catch (NesRomException e) {
			throw new RuntimeException(e);
		}

		try {
			NesMapper mapper = NesMapper.getMapper(rom.header.mapper);
			mapper.updateMemoryMapForRom(rom, program, monitor);
		} catch (LockException | MemoryConflictException | AddressOverflowException | DuplicateNameException | UnimplementedNesMapperException e) {
			throw new RuntimeException(e);
		}

		try {
			AddressSpace addressSpace = program.getAddressFactory().getDefaultAddressSpace();
			SymbolTable symbolTable = program.getSymbolTable();
			Memory memory =  program.getMemory();

			Address nmiAddress = addressSpace.getAddress(0xFFFA);
			createPinnedLabel(symbolTable, nmiAddress, "NMI");
			symbolTable.addExternalEntryPoint(nmiAddress);

			Address resAddress = addressSpace.getAddress(0xFFFC);
			createPinnedLabel(symbolTable, resAddress, "RES");
			symbolTable.addExternalEntryPoint(resAddress);

			Address irqAddress = addressSpace.getAddress(0xFFFE);
			createPinnedLabel(symbolTable, irqAddress, "IRQ");
			symbolTable.addExternalEntryPoint(irqAddress);

			Address nmiTargetAddress = getLittleEndianAddress(addressSpace, memory, nmiAddress);

			Address resTargetAddress = getLittleEndianAddress(addressSpace, memory, resAddress);

			Address irqTargetAddress = getLittleEndianAddress(addressSpace, memory, irqAddress);

			Symbol nmiTargetSymbol = symbolTable.createLabel(nmiTargetAddress, "vblank", SourceType.IMPORTED);
			symbolTable.addExternalEntryPoint(nmiTargetAddress);

			Symbol resTargetSymbol = symbolTable.createLabel(resTargetAddress, "reset", SourceType.IMPORTED);
			symbolTable.addExternalEntryPoint(resTargetAddress);

			Symbol irqTargetSymbol = symbolTable.createLabel(irqTargetAddress, "irq", SourceType.IMPORTED);
			symbolTable.addExternalEntryPoint(irqTargetAddress);

			// RES should have the highest precedence, followed by NMI, followed by IRQ. We set them
			// as primary in reverse order because the last `.setPrimary()` call has precedence
			irqTargetSymbol.setPrimary();
			nmiTargetSymbol.setPrimary();
			resTargetSymbol.setPrimary();

			MakeSym(program, monitor, log, 0x2000, 1, "PPUCTRL");
			MakeSym(program, monitor, log, 0x2001, 1, "PPUMASK");
			MakeSym(program, monitor, log, 0x2002, 1, "PPUSTATUS");
			MakeSym(program, monitor, log, 0x2003, 1, "OAMADDR");
			MakeSym(program, monitor, log, 0x2004, 1, "OAMDATA");
			MakeSym(program, monitor, log, 0x2005, 1, "PPUSCROLL");
			MakeSym(program, monitor, log, 0x2006, 1, "PPUADDR");
			MakeSym(program, monitor, log, 0x2007, 1, "PPUDATA");
			MakeSym(program, monitor, log, 0x4000, 4, "APU_SND_SQUARE1_REG");
			MakeSym(program, monitor, log, 0x4004, 4, "APU_SND_SQUARE2_REG");
			MakeSym(program, monitor, log, 0x4008, 4, "APU_SND_TRIANGLE_REG");
			MakeSym(program, monitor, log, 0x400c, 2, "APU_NOISE_REG");
			MakeSym(program, monitor, log, 0x4010, 4, "APU_DELTA_REG");
			MakeSym(program, monitor, log, 0x4014, 1, "OAMDMA");
			MakeSym(program, monitor, log, 0x4015, 1, "APU_MASTERCTRL_REG");
			MakeSym(program, monitor, log, 0x4016, 1, "JOYPAD_PORT1");
			MakeSym(program, monitor, log, 0x4017, 1, "JOYPAD_PORT2");
		} catch (InvalidInputException | AddressOutOfBoundsException | MemoryAccessException e) {
			throw new RuntimeException(e);
		}
	}

	private static void createPinnedLabel(final SymbolTable symbolTable, final Address address, final String label) throws InvalidInputException {
		Symbol nmiSymbol = symbolTable.createLabel(address, label, SourceType.IMPORTED);
		nmiSymbol.setPinned(true);
		nmiSymbol.setPrimary();
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		List<Option> list =
			super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);

		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {
		return super.validateOptions(provider, loadSpec, options, program);
	}

	@Override
	protected void createDefaultMemoryBlocks(Program program, Language language, MessageLog log) {
		// NOTE: We skip the default memory blocks because Ghidra's default 6502 memory map
		// differs from the NES's memory map
//		super.createDefaultMemoryBlocks(program, language, log);

		try {
			int ramPermissions =
				MemoryBlockDescription.READ | MemoryBlockDescription.WRITE | MemoryBlockDescription.EXECUTE;
			int ppuPermissions =
					MemoryBlockDescription.READ | MemoryBlockDescription.WRITE | MemoryBlockDescription.VOLATILE;
			int apuIoPermissions =
					MemoryBlockDescription.READ | MemoryBlockDescription.WRITE | MemoryBlockDescription.VOLATILE;

			// TODO: Refactor mirrored sections!
			MemoryBlockDescription.uninitialized(0x0000, 0x0800, "RAM", ramPermissions, false)
				.create(program);
			MemoryBlockDescription.byteMapped(0x0800, 0x0800, "RAM_MIRROR_1", ramPermissions, 0x0000)
				.create(program);
			MemoryBlockDescription.byteMapped(0x1000, 0x0800, "RAM_MIRROR_2", ramPermissions, 0x0000)
				.create(program);
			MemoryBlockDescription.byteMapped(0x1800, 0x0800, "RAM_MIRROR_3", ramPermissions, 0x0000)
				.create(program);
			MemoryBlockDescription.byteMapped(0x2008, 0x0008, "PPU_MIRROR_1", ppuPermissions, 0x2000)
				.create(program);
			MemoryBlockDescription.byteMapped(0x2010, 0x0010, "PPU_MIRROR_2", ppuPermissions, 0x2000)
				.create(program);
			MemoryBlockDescription.byteMapped(0x2020, 0x0020, "PPU_MIRROR_3", ppuPermissions, 0x2000)
				.create(program);
			MemoryBlockDescription.byteMapped(0x2040, 0x0040, "PPU_MIRROR_4", ppuPermissions, 0x2000)
				.create(program);
			MemoryBlockDescription.byteMapped(0x2080, 0x0080, "PPU_MIRROR_5", ppuPermissions, 0x2000)
				.create(program);
			MemoryBlockDescription.byteMapped(0x2100, 0x0100, "PPU_MIRROR_6", ppuPermissions, 0x2000)
				.create(program);
			MemoryBlockDescription.byteMapped(0x2200, 0x0200, "PPU_MIRROR_7", ppuPermissions, 0x2000)
				.create(program);
			MemoryBlockDescription.byteMapped(0x2400, 0x0400, "PPU_MIRROR_8", ppuPermissions, 0x2000)
				.create(program);
			MemoryBlockDescription.byteMapped(0x2800, 0x0800, "PPU_MIRROR_9", ppuPermissions, 0x2000)
				.create(program);
			MemoryBlockDescription.byteMapped(0x3000, 0x1000, "PPU_MIRROR_10", ppuPermissions, 0x2000)
				.create(program);

		} catch (LockException e) {
			throw new RuntimeException(e);
		} catch (DuplicateNameException e) {
			throw new RuntimeException(e);
		} catch (MemoryConflictException e) {
			throw new RuntimeException(e);
		} catch (AddressOverflowException e) {
			throw new RuntimeException(e);
		} catch (CancelledException e) {
			throw new RuntimeException(e);
		}
	}

	private void MakeSym(Program program, TaskMonitor monitor, MessageLog log, int address, int size, String name) {
		try {
			Address addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(address);
			MemoryBlock block = program.getMemory().createInitializedBlock(name, addr, size, (byte)0x00, monitor, false);
			block.setRead(true);
			block.setWrite(true);
			block.setExecute(false);
			program.getSymbolTable().createLabel(addr, name, SourceType.IMPORTED);
		}catch(Exception e) {
			log.appendException(e);
		}
	}
}
