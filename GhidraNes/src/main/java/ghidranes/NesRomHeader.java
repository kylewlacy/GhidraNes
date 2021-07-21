package ghidranes;

import java.io.IOException;
import java.io.InputStream;

import ghidranes.errors.InvalidNesRomHeaderException;
import ghidranes.errors.NesRomEofException;

public class NesRomHeader {
	protected int prgRomSizeBytes;
	protected int chrRomSizeBytes;
	protected int prgRamSizeBytes;
	protected boolean hasPersistence;
	protected boolean hasTrainer;
	protected int mapper;

	public NesRomHeader(InputStream bytes) throws NesRomEofException, InvalidNesRomHeaderException, IOException {
		byte[] magicBytes = bytes.readNBytes(4);
		if (magicBytes.length < 4) {
			throw new NesRomEofException();
		}
		if (magicBytes[0] != 'N' || magicBytes[1] != 'E' && magicBytes[2] != 'S' && magicBytes[3] != 0x1A) {
			throw new InvalidNesRomHeaderException("Input is not a valid NES ROM");
		}

		int prgRomSizeField = bytes.read();
		if (prgRomSizeField < 0) {
			throw new NesRomEofException();
		}

		int chrRomSizeField = bytes.read();
		if (chrRomSizeField < 0) {
			throw new NesRomEofException();
		}

		int flags6 = bytes.read();
		if (flags6 < 0) {
			throw new NesRomEofException();
		}

		int flags7 = bytes.read();
		if (flags7 < 0) {
			throw new NesRomEofException();
		}

		int prgRamSizeField = bytes.read();
		if (prgRamSizeField < 0) {
			throw new NesRomEofException();
		}

		int flags9 = bytes.read();
		if (flags9 < 0) {
			throw new NesRomEofException();
		}

		int flags10 = bytes.read();
		if (flags10 < 0) {
			throw new NesRomEofException();
		}

		byte[] padding = bytes.readNBytes(5);
		if (padding.length < 5) {
			throw new NesRomEofException();
		}

//		boolean flagMirrorBit         = (flags6 & 0b0000_0001) != 0;
		boolean flagPersistentBit     = (flags6 & 0b0000_0010) != 0;
		boolean flagTrainerBit        = (flags6 & 0b0000_0100) != 0;
//		boolean flagFourScreenVramBit = (flags6 & 0b0000_1000) != 0;
		int flagMapperLo              = (flags6 & 0b1111_0000) >> 4;

//		boolean flagVsUnisystem       = (flags7 & 0b0000_0001) != 0;
//		boolean flagPlaychoice10      = (flags7 & 0b0000_0010) != 0;
		int flagRomFormat             = (flags7 & 0b0000_1100) >> 2;
		int flagMapperHi              = (flags7 & 0b1111_0000) >> 4;

		// Fields in flag 9 are ignored

//		int flagTvSystem              = (flags10 & 0b0000_0011);
		boolean flagPrgRamBit         = (flags10 & 0b0001_0000) != 0;
//		boolean busConflictBit        = (flags10 & 0b0010_0000) != 0;

		this.prgRomSizeBytes = prgRomSizeField * 16_384;
		this.chrRomSizeBytes = chrRomSizeField * 8_192;
		if (flagPrgRamBit) {
			if (prgRamSizeField == 0) {
                // When a ROM has the PRG RAM bit set but has a PRG RAM
                // size of 0, then a fallback size of 8KB is used
				this.prgRamSizeBytes = 8_192;
			}
			else {
				this.prgRamSizeBytes = prgRamSizeField * 8_192;
			}
		}
		else {
			this.prgRamSizeBytes = 0;
		}

		this.hasPersistence = flagPersistentBit;
		this.hasTrainer = flagTrainerBit;

		this.mapper = flagMapperLo | (flagMapperHi << 4);

		if (flagRomFormat == 2) {
			// TODO: Handle NES 2.0 format
		}
	}

	int getPrgRomSizeBytes() {
		return this.prgRamSizeBytes;
	}

	int getChrRomSizeBytes() {
		return this.chrRomSizeBytes;
	}

	int getPrgRamSizeBytes() {
		return this.prgRamSizeBytes;
	}

	boolean getHasPersistence() {
		return this.hasPersistence;
	}

	boolean getHasTrainer() {
		return this.hasTrainer;
	}

	int getMapper() {
		return this.mapper;
	}
}
