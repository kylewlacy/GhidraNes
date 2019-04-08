package ghidranes.errors;

public class NesRomEofException extends NesRomException {
	public NesRomEofException() {
		super("Encountered unexpected EOF when reading NES ROM");
	}
}
