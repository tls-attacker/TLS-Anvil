/**
 *  TLS-Test-Framework - A framework for modeling TLS tests
 *
 *  Copyright 2020 Ruhr University Bochum and
 *  TÜV Informationstechnik GmbH
 *
 *  Licensed under Apache License 2.0
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

package de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Represents a value of a ConfigurationOptionDerivationParameter. This value can be a flag (option is set or not set),
 * or one or multiple Strings as option values.
 */
public class ConfigurationOptionValue {
    private boolean optionIsSet;
    private List<String> stringValues;

    private boolean isFlag;

    /**
     * Constructor for flags.
     *
     * @param flagValue - Pass true if the respective flag should be set, false if not.
     */
    public ConfigurationOptionValue(boolean flagValue){
        this.isFlag = true;
        this.optionIsSet = flagValue;
    }

    /**
     * Constructor for a single string value. Using this constructor represents that the respective option is set
     * with the specified option string. (E.g. in 'InstallDir=/my/path/': '/my/path/' would be the string value
     * for the option 'InstallDir'). The respective ConfigurationOptionBuildManager is responsible for interpreting
     * the specified string.
     *
     * @param optionValue - the option value
     */
    public ConfigurationOptionValue(String optionValue){
        this.isFlag = false;
        this.optionIsSet = true;
        stringValues = Arrays.asList(optionValue);
    }

    /**
     * Constructor for multiple string values. Using this constructor represents that the respective option is set
     * with the specified option strings (in order). The respective ConfigurationOptionBuildManager is responsible for interpreting
     * the specified strings.
     *
     * @param optionValues - the option value
     */
    public ConfigurationOptionValue(List<String> optionValues){
        this.isFlag = false;
        this.optionIsSet = true;
        stringValues = new ArrayList<>(optionValues);
    }

    /**
     * Returns true iff the value is a flag, i.e. it contains no option value (list).
     *
     * @returns true iff the value is a flag
     */
    public boolean isFlag(){
        return isFlag;
    }

    /**
     * Returns true if the option is set, i.e. it is no non-set flag.
     *
     * @return true if the option is set
     */
    public boolean isOptionSet(){
        return optionIsSet;
    }

    /**
     * Returns the list of passed option values. If the one-value constructor was called this function returns a
     * list with one element. If the this Value is a flag an empty list is returned.
     *
     * @returns the option values as a String List
     */
    public List<String> getOptionValues(){
        if(isFlag){
            return new ArrayList<>();
        }
        else{
            return new ArrayList<>(stringValues);
        }
    }


}
