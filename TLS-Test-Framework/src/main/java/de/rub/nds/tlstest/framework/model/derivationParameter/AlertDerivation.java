/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.model.derivationParameter;

import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlstest.framework.anvil.TlsDerivationParameter;
import de.rub.nds.tlstest.framework.model.TlsParameterType;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

public class AlertDerivation extends TlsDerivationParameter<AlertDescription> {

    public AlertDerivation() {
        super(TlsParameterType.ALERT, AlertDescription.class);
    }

    public AlertDerivation(AlertDescription selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }

    @Override
    public List<DerivationParameter<Config, AlertDescription>> getParameterValues(
            DerivationScope derivationScope) {
        List<DerivationParameter<Config, AlertDescription>> parameterValues = new LinkedList<>();
        Arrays.stream(AlertDescription.values())
                .forEach(descr -> parameterValues.add(new AlertDerivation(descr)));
        return parameterValues;
    }

    @Override
    protected TlsDerivationParameter<AlertDescription> generateValue(
            AlertDescription selectedValue) {
        return new AlertDerivation(selectedValue);
    }
}
