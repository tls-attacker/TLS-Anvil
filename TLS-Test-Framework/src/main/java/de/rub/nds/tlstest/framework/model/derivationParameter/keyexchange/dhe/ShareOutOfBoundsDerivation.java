/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.model.derivationParameter.keyexchange.dhe;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.model.LegacyDerivationScope;
import de.rub.nds.tlstest.framework.model.TlsParameterType;
import de.rub.nds.tlstest.framework.model.derivationParameter.DerivationParameter;
import java.math.BigInteger;
import java.util.LinkedList;
import java.util.List;

public class ShareOutOfBoundsDerivation
        extends DerivationParameter<ShareOutOfBoundsDerivation.OutOfBoundsType> {

    // share minus p wasn't useful
    // numbers in TLS are unsigned - negative numbers do not exist
    // therefore this would not test bound validation but errors in
    // (de)serialisation
    public enum OutOfBoundsType {
        SHARE_PLUS_P,
        SHARE_IS_ONE,
        SHARE_IS_ZERO
    }

    public ShareOutOfBoundsDerivation() {
        super(TlsParameterType.FFDHE_SHARE_OUT_OF_BOUNDS, OutOfBoundsType.class);
    }

    public ShareOutOfBoundsDerivation(OutOfBoundsType selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }

    @Override
    public List<DerivationParameter> getParameterValues(
            TestContext context, LegacyDerivationScope scope) {
        List<DerivationParameter> parameterValues = new LinkedList<>();
        for (OutOfBoundsType type : OutOfBoundsType.values()) {
            parameterValues.add(new ShareOutOfBoundsDerivation(type));
        }
        return parameterValues;
    }

    @Override
    public void applyToConfig(Config config, TestContext context) {
        if (config.getDefaultRunningMode() == RunningModeType.CLIENT) {
            throw new UnsupportedOperationException(
                    "This Derivation has to be configured manually if used as a client (use @ManualConfig)");
        } else {
            BigInteger pubShare;
            switch (getSelectedValue()) {
                case SHARE_IS_ZERO:
                    config.setDefaultServerDhPrivateKey(BigInteger.ZERO);
                    config.setDefaultServerDhPublicKey(BigInteger.ZERO);
                    break;
                case SHARE_IS_ONE:
                    config.setDefaultServerDhPrivateKey(BigInteger.ZERO);
                    config.setDefaultServerDhPublicKey(BigInteger.ONE);
                    break;
                case SHARE_PLUS_P:
                    pubShare = config.getDefaultServerDhPublicKey();
                    pubShare = pubShare.add(config.getDefaultServerDhModulus());
                    config.setDefaultServerDhPublicKey(pubShare);
                    break;
            }
        }
    }
}
