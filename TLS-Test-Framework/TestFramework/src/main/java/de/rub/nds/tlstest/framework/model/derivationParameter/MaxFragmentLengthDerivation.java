/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.model.derivationParameter;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.MaxFragmentLength;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.model.DerivationScope;
import de.rub.nds.tlstest.framework.model.DerivationType;
import java.util.LinkedList;
import java.util.List;

/**
 * Derivation for the max_fragment_length extension
 *
 * <p>If the parameter is null no extension is included
 */
public class MaxFragmentLengthDerivation extends DerivationParameter<MaxFragmentLength> {

    public MaxFragmentLengthDerivation() {
        super(DerivationType.MAX_FRAGMENT_LENGTH, MaxFragmentLength.class);
    }

    public MaxFragmentLengthDerivation(MaxFragmentLength selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }

    public List<DerivationParameter> getParameterValues(
            TestContext context, DerivationScope scope) {
        List<DerivationParameter> parameterValues = new LinkedList<>();

        // TODO The layer system fails to process messages when max length was set
        for (MaxFragmentLength maxFragmentLength : MaxFragmentLength.values()) {
            parameterValues.add(new MaxFragmentLengthDerivation(maxFragmentLength));
        }

        // A parameter where no max fragment length extension is included
        parameterValues.add(new MaxFragmentLengthDerivation(null));

        return parameterValues;
    }

    @Override
    public void applyToConfig(Config config, TestContext context) {
        MaxFragmentLength selectedValue = getSelectedValue();

        if (selectedValue != null) {
            config.setDefaultMaxFragmentLength(selectedValue);
            config.setAddMaxFragmentLengthExtension(true);
        }
    }
}
