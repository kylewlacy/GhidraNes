package ghidranes.util;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;

/**
 *
 */
public class AddressSpaceUtil {
    public static Address getLittleEndianAddress(final AddressSpace addressSpace, final Memory memory, final Address irqAddress) throws MemoryAccessException {
        byte irqLo = memory.getByte(irqAddress);
        byte irqHi = memory.getByte(irqAddress.add(1));
        long irq = (Byte.toUnsignedLong(irqHi) << 8) | Byte.toUnsignedLong(irqLo);
        return addressSpace.getAddress(irq);
    }
}
