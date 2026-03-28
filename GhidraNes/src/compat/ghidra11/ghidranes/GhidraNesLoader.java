package ghidranes;

import java.io.IOException;
import java.util.List;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Ghidra 11 (and earlier) adapter. Bridges the old loader API to the
 * shared implementation in GhidraNesLoaderBase.
 */
public class GhidraNesLoader extends GhidraNesLoaderBase {

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {
		doLoad(provider, options, program, monitor, log);
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		List<Option> list =
			super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);
		return doGetDefaultOptions(provider, loadSpec, list);
	}

	@Override
	protected void createDefaultMemoryBlocks(Program program, Language language, MessageLog log) {
		doCreateDefaultMemoryBlocks(program);
	}
}
