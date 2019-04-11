package ghidranes.errors;

public class UnimplementedNesMapperException extends NesRomException {
	public UnimplementedNesMapperException(int mapperNum) {
		super("Tried to load ROM with unimplemented mapper " + mapperNum);
	}
}