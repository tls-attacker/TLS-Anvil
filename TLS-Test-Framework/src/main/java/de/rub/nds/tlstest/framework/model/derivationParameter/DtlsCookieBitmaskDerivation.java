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
import de.rub.nds.tlstest.framework.anvil.TlsDerivationParameter;
import de.rub.nds.tlstest.framework.model.TlsParameterType;
import java.util.LinkedList;
import java.util.List;

/** Provides a modification bitmask for HelloVerifyRequest and second ClientHello cookie. */
public class DtlsCookieBitmaskDerivation extends TlsDerivationParameter<Integer> {

    public DtlsCookieBitmaskDerivation() {
        super(TlsParameterType.DTLS_COOKIE_BITMASK, Integer.class);
    }

    public DtlsCookieBitmaskDerivation(Integer selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }

    @Override
    public List<DerivationParameter<Config, Integer>> getParameterValues(DerivationScope scope) {
        List<DerivationParameter<Config, Integer>> parameterValues = new LinkedList<>();

        for (int i = 0; i < context.getConfig().createConfig().getDtlsDefaultCookieLength(); i++) {
            parameterValues.add(new DtlsCookieBitmaskDerivation(i));
        }
        return parameterValues;
    }

    @Override
    protected TlsDerivationParameter<Integer> generateValue(Integer selectedValue) {
        return new DtlsCookieBitmaskDerivation(selectedValue);
    }
}
