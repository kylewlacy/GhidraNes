package ghidranes.util;

import java.util.ArrayList;
import java.util.Arrays;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;

public class NesMmio {
	public Address address;
	public String name;
	public NesMmio(AddressSpace addressSpace, int _address, String _name) {
		address = addressSpace.getAddress(_address);
		name = _name;
	}

	public static ArrayList<NesMmio> getDefaultRegisters(AddressSpace addressSpace) {
		return new ArrayList<>(Arrays.asList(
				new NesMmio(addressSpace, 0x2000, "PPUCTRL"),
				new NesMmio(addressSpace, 0x2001, "PPUMASK"),
				new NesMmio(addressSpace, 0x2002, "PPUSTATUS"),
				new NesMmio(addressSpace, 0x2003, "OAMADDR"),
				new NesMmio(addressSpace, 0x2004, "OAMDATA"),
				new NesMmio(addressSpace, 0x2005, "PPUSCROLL"),
				new NesMmio(addressSpace, 0x2006, "PPUADDR"),
				new NesMmio(addressSpace, 0x2007, "PPUDATA"),
				new NesMmio(addressSpace, 0x4000, "SQ1_VOL"),
				new NesMmio(addressSpace, 0x4001, "SQ1_SWEEP"),
				new NesMmio(addressSpace, 0x4002, "SQ1_LO"),
				new NesMmio(addressSpace, 0x4003, "SQ1_HI"),
				new NesMmio(addressSpace, 0x4004, "SQ2_VOL"),
				new NesMmio(addressSpace, 0x4005, "SQ2_SWEEP"),
				new NesMmio(addressSpace, 0x4006, "SQ2_LO"),
				new NesMmio(addressSpace, 0x4007, "SQ2_HI"),
				new NesMmio(addressSpace, 0x4008, "TRI_LINEAR"),
				new NesMmio(addressSpace, 0x400a, "TRI_LO"),
				new NesMmio(addressSpace, 0x400b, "TRI_HI"),
				new NesMmio(addressSpace, 0x400c, "NOISE_VOL"),
				new NesMmio(addressSpace, 0x400e, "NOISE_LO"),
				new NesMmio(addressSpace, 0x400f, "NOISE_HI"),
				new NesMmio(addressSpace, 0x4010, "DMC_FREQ"),
				new NesMmio(addressSpace, 0x4011, "DMC_RAW"),
				new NesMmio(addressSpace, 0x4012, "DMC_START"),
				new NesMmio(addressSpace, 0x4013, "DMC_LEN"),
				new NesMmio(addressSpace, 0x4014, "OAMDMA"),
				new NesMmio(addressSpace, 0x4015, "SND_CHN"),
				new NesMmio(addressSpace, 0x4016, "JOY1"),
				new NesMmio(addressSpace, 0x4017, "JOY2")
		));
	}
}
