package ghidranes.util;

import java.awt.Component;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.swing.DefaultComboBoxModel;

import docking.widgets.combobox.GhidraComboBox;
import ghidra.app.util.Option;


public class ChrBankOption extends Option {

    private static final String OPTION_VALUE_SKIP = "Don't import CHR ROM banks";
    private static final String OPTION_VALUE_ONE = "Create a single CHR ROM block";
    private static final String OPTION_VALUE_CREATE_PREFIX = "Create CHR ROM banks of size ";
    private static final String OPTION_VALUE_CREATE_SUFFIX = "Kbytes";

    public static final int SKIP = 0; 
    public static final int ONE = -1;

    protected List<Integer> chrBankSizes;
    private GhidraComboBox<String> listbox;
    
    
    public ChrBankOption(String name, List<Integer> chrBankSizes) {
        this(name, chrBankSizes, SKIP);
    }

    protected ChrBankOption(String name, List<Integer> chrBankSizes, int defaultValue) {
        super(name, defaultValue);

        this.chrBankSizes = chrBankSizes;
        this.listbox = null;

        //Msg.info("ChrBankOption", "Created with name: " + name);        
    }

    private static String getOptionText(int size) {
        switch (size) {
            case SKIP:
                return OPTION_VALUE_SKIP;
            case ONE:
                return OPTION_VALUE_ONE;
            default:
                return String.format("%s%d%s", OPTION_VALUE_CREATE_PREFIX, size/1024, OPTION_VALUE_CREATE_SUFFIX);
        }
    }

    private static int getOptionInt(String text) {
        // handle special cases
        if (text.equals(OPTION_VALUE_SKIP)) {
            return SKIP;
        } else if (text.equals(OPTION_VALUE_ONE)) {
            return ONE;
        }
        String textInt = text.substring(OPTION_VALUE_CREATE_PREFIX.length(), 
            text.length() - OPTION_VALUE_CREATE_SUFFIX.length());
        return Integer.parseInt(textInt) * 1024;
    }

    @Override
    public Component getCustomEditorComponent() {
        // this is based loosely on ghidra.app.util.OptionsEditorPanel.getAddressSpaceEditorComponent()
		// set the list of valid values based on the possible bank sizes
		DefaultComboBoxModel<String> lm = new DefaultComboBoxModel<String>();
        lm.addElement(OPTION_VALUE_SKIP); // add the "skip" option first
        lm.addElement(OPTION_VALUE_ONE); // add "single" option next

        List<Integer> workSizes = new ArrayList<Integer>(chrBankSizes);
        workSizes.sort(Collections.reverseOrder()); // sort descending
        for (int size : workSizes) {
            lm.addElement(getOptionText(size));
        }   
		
	    this.listbox = new GhidraComboBox<String>(lm);
		listbox.setSelectedItem(getValue());
		listbox.setPrototypeDisplayValue(getOptionText(Collections.max(chrBankSizes))); // set the width of the listbox to longest text
        listbox.addItemListener(e -> {
			// called whenever the listbox changes to push the value back to the Option that is
			// our 'model'
            //Msg.info("BankAddressOptionIL", this.getName() + " listbox selection changed: " + listbox.getSelectedItem());
			if (listbox.getSelectedItem() != null) {
				this.setValue(getOptionInt((String)listbox.getSelectedItem()));
                //Msg.info("BankAddressOptionIL", this.getName() + " set value to: " + this.getValue());
			}
		});

    	return listbox;
	}

    @Override
    public Option copy() {
        return new ChrBankOption(getName(), chrBankSizes, (int)getValue());
    }
}
