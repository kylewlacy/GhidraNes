package ghidranes;

import java.io.IOException;
import java.io.InputStream;
import ghidranes.errors.NesRomEofException;

public class NesRom {
	public NesRomHeader header;
	byte[] trainerBytes;
	public byte[] prgRom;
	byte[] chrRom;

	public NesRom(NesRomHeader romHeader, InputStream bytes) throws NesRomEofException, IOException {
		if (romHeader.hasTrainer) {
			trainerBytes = bytes.readNBytes(512);
			if (trainerBytes.length < 512) {
				throw new NesRomEofException();
			}
		}
		else {
			trainerBytes = new byte[0];
		}

		byte[] prgRomBytes = bytes.readNBytes(romHeader.prgRomSizeBytes);
		if (prgRomBytes.length < romHeader.prgRomSizeBytes) {
			throw new NesRomEofException();
		}

		byte[] chrRomBytes = bytes.readNBytes(romHeader.chrRomSizeBytes);
		if (chrRomBytes.length < romHeader.chrRomSizeBytes) {
			throw new NesRomEofException();
		}

		this.header = romHeader;
		this.prgRom = prgRomBytes;
		this.chrRom = chrRomBytes;
	}
}
