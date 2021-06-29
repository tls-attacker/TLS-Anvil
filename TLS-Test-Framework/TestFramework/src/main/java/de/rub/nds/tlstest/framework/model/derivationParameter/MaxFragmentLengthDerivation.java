/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.model.derivationParameter;

import com.fasterxml.jackson.annotation.JsonValue;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.MaxFragmentLength;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.model.DerivationScope;
import de.rub.nds.tlstest.framework.model.DerivationType;

import java.util.AbstractMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 * Derivation for the max_fragment_length extension
 *
 * The parameter type is a pair of [Boolean, MaxFragmentLength].
 * If the first value is true the extension is included with the fragment length of the second value.
 * If the first value is false the extension is not included. The second value is ignored in this case.
 */
public class MaxFragmentLengthDerivation extends DerivationParameter<Map.Entry<Boolean, MaxFragmentLength>> {

    public MaxFragmentLengthDerivation() {
        super(DerivationType.MAX_FRAGMENT_LENGTH, (Class<Map.Entry<Boolean, MaxFragmentLength>>)
                ((Map.Entry<Boolean, MaxFragmentLength>)
                (new AbstractMap.SimpleImmutableEntry<>(false, MaxFragmentLength.TWO_9)))
                .getClass());
    }

    public MaxFragmentLengthDerivation(Map.Entry<Boolean, MaxFragmentLength> selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }

    public List<DerivationParameter> getParameterValues(TestContext context, DerivationScope scope) {
        List<DerivationParameter> parameterValues = new LinkedList<>();

        for(MaxFragmentLength maxFragmentLength : MaxFragmentLength.values()){
            Map.Entry<Boolean, MaxFragmentLength> pair = new AbstractMap.SimpleImmutableEntry<Boolean, MaxFragmentLength>(true, maxFragmentLength);
            parameterValues.add(new MaxFragmentLengthDerivation(pair));
        }

        // A parameter where no max fragment length extension is included
        Map.Entry<Boolean, MaxFragmentLength> pair = new AbstractMap.SimpleImmutableEntry<Boolean, MaxFragmentLength>(false, MaxFragmentLength.TWO_9);
        parameterValues.add(new MaxFragmentLengthDerivation(pair));

        return parameterValues;
    }

    @Override
    public void applyToConfig(Config config, TestContext context) {
        Map.Entry<Boolean, MaxFragmentLength> selectedValue = getSelectedValue();
        boolean includeAddMaxFragmentExtension = selectedValue.getKey();
        MaxFragmentLength maxFragmentLength = selectedValue.getValue();

        if (includeAddMaxFragmentExtension) {
            config.setMaxFragmentLength(maxFragmentLength);
            config.setAddMaxFragmentLengthExtension(true);
        }
        else {
            config.setAddMaxFragmentLengthExtension(false);
        }
    }

    @Override
    @JsonValue
    public String jsonValue() {
        Map.Entry<Boolean, MaxFragmentLength> selectedValue = getSelectedValue();
        boolean includeAddMaxFragmentExtension = selectedValue.getKey();
        MaxFragmentLength maxFragmentLength = selectedValue.getValue();

        if(includeAddMaxFragmentExtension){
            return "" + maxFragmentLength;
        }
        else{
            return "EXTENSION_NOT_INCLUDED";
        }
    }

}


