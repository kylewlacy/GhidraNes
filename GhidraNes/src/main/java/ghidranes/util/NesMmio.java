package ghidranes.util;

import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.Address;

public class NesMmio {
	public Address address;
	public String name;
	public NesMmio(AddressSpace addressSpace, int _address, String _name) {
		address = addressSpace.getAddress(_address);
		name = _name;
	}
}
