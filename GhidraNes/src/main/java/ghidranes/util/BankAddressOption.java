package ghidranes.util;

import java.awt.Component;

import javax.swing.DefaultComboBoxModel;

import docking.widgets.combobox.GhidraComboBox;
import ghidra.app.util.Option;

/* TODO: it is likely possible (and desirable) to more cleanly separate the data
   model (essentially a list of addresses) from the text shown in the listbox
*/
public class BankAddressOption extends Option {

    private GhidraComboBox<String> listbox;
    
    protected int bankSize;
    protected int baseAddress;
    protected int defaultAddress;
    
    public BankAddressOption(String name, String group, int bankSize, int baseAddress, int defaultAddress) {
        super(name, String.class, getOptionText(defaultAddress), null, group);

        this.bankSize = bankSize;
        this.baseAddress = baseAddress;
        this.defaultAddress = defaultAddress;
        this.listbox = null;

          //Msg.info("BankAddressOption", "Created with name: " + name);
    }

    private static String getOptionText(int addr) {
        // handle special case of 0, which means "All"
        if (addr == 0) {
            return "All";
        }
        return String.format("%04x", addr);
    }

    private static int getOptionInt(String text) {
        // handle special case of "All", which means 0
        if (text.equals("All")) {
            return 0;
        }
        return Integer.parseInt(text, 16);
    }

    @Override
    public Component getCustomEditorComponent() {
        // this is based loosely on ghidra.app.util.OptionsEditorPanel.getAddressSpaceEditorComponent()
		// set the list of valid values based on the bank size and base
		DefaultComboBoxModel<String> lm = new DefaultComboBoxModel<String>();
		for (int addr = baseAddress; addr < 0x10000; addr += bankSize) {
			lm.addElement(getOptionText(addr));
		}
        lm.addElement("All");
		
	    this.listbox = new GhidraComboBox<String>(lm);
		listbox.setSelectedItem(getOptionText(defaultAddress));
		listbox.setPrototypeDisplayValue("0000"); // set the width of the listbox to 4 characters
        listbox.addItemListener(e -> {
			// called whenever the listbox changes to push the value back to the Option that is
			// our 'model'
            //Msg.info("BankAddressOptionIL", "in IL");
            //Msg.info("BankAddressOptionIL", this.getName() + " listbox selection changed: " + listbox.getSelectedItem());
			if (listbox.getSelectedItem() != null) {
				this.setValue(listbox.getSelectedItem());
                //Msg.info("BankAddressOptionIL", this.getName() + " set value to: " + this.getValue());
			}
		});

        //Msg.info("BankAddressOption", "getCustomEditorComponent " + this.getName() + " returning as selected " + listbox.getSelectedItem());
    	return listbox;
	}

    @Override
    public Option copy() {
        //Msg.info("BankAddressOption", "copy called");
        return new BankAddressOption(getName(), getGroup(), bankSize, baseAddress, getOptionInt((String)getValue()));
    }
}
