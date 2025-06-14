package ghidranes.util;

// this probably belongs in NesMapper eventually
public class Bank {
	public static String getPrgBankName(int bankIndex, int bankCount) {
		String format = "PRG%0" +  Integer.toString(bankCount).length() + "d";
		return String.format(format, bankIndex);
	}

	public static String getBankName(int bankIndex, int bankCount, int baseAddress) {
		String bankName = getPrgBankName(bankIndex, bankCount);
		if (baseAddress == 0) {
			return bankName;
		} else {
			// e.g. PRG15_8 or PRG7_A
			return String.format("%s_%01X", bankName, baseAddress / 0x1000);
		}
	}

    public static String getChrBankName(int bankIndex, int bankCount) {
		String format = "CHR%0" + Integer.toString(bankCount).length() + "d";
		return String.format(format, bankIndex);
	}
}
