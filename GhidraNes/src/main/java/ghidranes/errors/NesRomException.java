package ghidranes.errors;

public class NesRomException extends Exception {
	public NesRomException() {
		super();
	}

	public NesRomException(String message) {
		super(message);
	}

	public NesRomException(Throwable cause) {
		super(cause);
	}

	public NesRomException(String message, Throwable cause) {
		super(message, cause);
	}

	public NesRomException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
		super(message, cause, enableSuppression, writableStackTrace);
	}
}
