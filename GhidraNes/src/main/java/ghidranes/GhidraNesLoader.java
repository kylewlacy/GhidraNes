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

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import ghidra.app.util.Option;
import ghidra.app.util.OptionUtils;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.framework.store.LockException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import ghidranes.errors.InvalidNesRomHeaderException;
import ghidranes.errors.NesRomException;
import ghidranes.errors.UnimplementedNesMapperException;
import ghidranes.util.MemoryBlockDescription;

/**
 * This loader parses an iNES ROM file and maps the PRG and CHR rom appropriately
 */
public class GhidraNesLoader extends AbstractProgramWrapperLoader {

	public static final String LOADER_NAME = "NES ROM";

	private static final String OPTION_NAME_MIRROR = "Create mirror blocks for RAM and IO";
	private static final Boolean OPTION_DEFAULT_MIRROR = true;

	// in theory you could (should?)"rebuild" the rom object in the methods that need
	// it from the ByteProvider instead of using a local variable here
	protected NesRom rom;

	private Boolean wantMirrors = OPTION_DEFAULT_MIRROR;

	@Override
	public String getName() {
		return LOADER_NAME;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		InputStream bytes = provider.getInputStream(0);

		try {
			// Try to parse the ROM header (will throw an exception if parsing fails)
			rom = new NesRom(bytes);

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

		// have to stash a local copy of the mirror option cause
		// createDefaultMemoryBlocks() doesn't have access the load options
		wantMirrors = shouldCreateMirrors(options);

		InputStream bytes = provider.getInputStream(0);
		NesRom rom;

		try {
			rom = new NesRom(bytes);
		} catch (NesRomException e) {
			throw new RuntimeException(e);
		}

		try {
			// create base ROM bank to overlay banks
			int romPermissions =
				MemoryBlockDescription.READ | MemoryBlockDescription.EXECUTE;
			MemoryBlockDescription.uninitialized(0x8000, 0x8000, "PRG_ROM", romPermissions, false)
				.create(program);
			
			// map the banks
			rom.applyMapper(program, monitor, options);
		} catch (LockException | MemoryConflictException | AddressOverflowException
				 | DuplicateNameException | InvalidInputException | UnimplementedNesMapperException
				 | InvalidNesRomHeaderException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		List<Option> list =
			super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);

		// general options
		list.add(new Option(OPTION_NAME_MIRROR, OPTION_DEFAULT_MIRROR));

		// identify ROM-specific options based on NES header info
		list.addAll(rom.getLoadOptions());

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
		// TODO: consider creating an NES "language" with the correct memory map

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
			if (wantMirrors) {
				MemoryBlockDescription.byteMapped(0x0800, 0x0800, "RAM_MIRROR_1", ramPermissions, 0x0000)
					.create(program);
				MemoryBlockDescription.byteMapped(0x1000, 0x0800, "RAM_MIRROR_2", ramPermissions, 0x0000)
					.create(program);
				MemoryBlockDescription.byteMapped(0x1800, 0x0800, "RAM_MIRROR_3", ramPermissions, 0x0000)
					.create(program);
			}
			MemoryBlockDescription.uninitialized(0x2000, 0x0008, "PPU", ppuPermissions, false)
				.create(program);
			if (wantMirrors) {
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
			}
			MemoryBlockDescription.uninitialized(0x4000, 0x0018, "APU_IO", apuIoPermissions, false)
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

	protected Boolean shouldCreateMirrors(List<Option> options) {
		return OptionUtils.getBooleanOptionValue(OPTION_NAME_MIRROR, options, OPTION_DEFAULT_MIRROR);
	}
}
