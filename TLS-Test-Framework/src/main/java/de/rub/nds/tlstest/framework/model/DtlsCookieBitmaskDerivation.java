/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.model.derivationParameter;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.model.DerivationScope;
import de.rub.nds.tlstest.framework.model.DerivationType;
import java.util.LinkedList;
import java.util.List;

/** Provides a modification bitmask for HelloVerifyRequest and second ClientHello cookie. */
public class DtlsCookieBitmaskDerivation extends DerivationParameter<Integer> {

    public DtlsCookieBitmaskDerivation() {
        super(DerivationType.DTLS_COOKIE_BITMASK, Integer.class);
    }

    public DtlsCookieBitmaskDerivation(Integer selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }

    @Override
    public List<DerivationParameter> getParameterValues(
            TestContext context, DerivationScope scope) {
        List<DerivationParameter> parameterValues = new LinkedList<>();

        for (int i = 0; i < context.getConfig().createConfig().getDtlsDefaultCookieLength(); i++) {
            parameterValues.add(new DtlsCookieBitmaskDerivation(i));
        }
        return parameterValues;
    }

    @Override
    public void applyToConfig(Config config, TestContext context) {}
}