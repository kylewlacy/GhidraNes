package ghidranes;

import java.io.IOException;
import java.util.List;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.Loader.ImporterSettings;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;

/**
 * Ghidra 12+ adapter. Bridges the new ImporterSettings-based loader API to
 * the shared implementation in GhidraNesLoaderBase.
 */
public class GhidraNesLoader extends GhidraNesLoaderBase {

	@Override
	protected void load(Program program, ImporterSettings settings)
			throws CancelledException, IOException {
		doLoad(settings.provider(), settings.options(), program, settings.monitor(), settings.log());
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram, boolean mirrorFsLayout) {
		List<Option> list =
			super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram,
				mirrorFsLayout);
		return doGetDefaultOptions(provider, loadSpec, list);
	}

	@Override
	protected void createDefaultMemoryBlocks(Program program, ImporterSettings settings) {
		doCreateDefaultMemoryBlocks(program);
	}
}
