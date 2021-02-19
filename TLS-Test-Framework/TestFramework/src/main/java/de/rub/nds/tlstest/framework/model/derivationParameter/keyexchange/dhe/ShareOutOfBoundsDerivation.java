package de.rub.nds.tlstest.framework.model.derivationParameter.keyexchange.dhe;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.model.DerivationScope;
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.model.constraint.ConditionalConstraint;
import de.rub.nds.tlstest.framework.model.derivationParameter.DerivationParameter;

public class ShareOutOfBoundsDerivation extends DerivationParameter<ShareOutOfBoundsDerivation.OutOfBoundsType> {

    public enum OutOfBoundsType {
        SHARE_PLUS_P, SHARE_MINUS_P, SHARE_IS_ONE,
    }

    public ShareOutOfBoundsDerivation() {
        super(DerivationType.FFDHE_SHARE_OUT_OF_BOUNDS, OutOfBoundsType.class);
    }

    public ShareOutOfBoundsDerivation(OutOfBoundsType selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }

    @Override
    public List<DerivationParameter> getParameterValues(TestContext context, DerivationScope scope) {
        List<DerivationParameter> parameterValues = new LinkedList<>();
        for (OutOfBoundsType typ : OutOfBoundsType.values()) {
            parameterValues.add(new ShareOutOfBoundsDerivation(typ));
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
                case SHARE_IS_ONE:
                    config.setDefaultServerDhPrivateKey(BigInteger.ZERO);
                    config.setDefaultServerDhPublicKey(BigInteger.ONE);
                    break;
                case SHARE_PLUS_P:
                    pubShare = config.getDefaultServerDhPublicKey();
                    pubShare = pubShare.add(config.getDefaultServerDhModulus());
                    config.setDefaultServerDhPublicKey(pubShare);
                    break;
                case SHARE_MINUS_P:
                    pubShare = config.getDefaultServerDhPublicKey();
                    pubShare = pubShare.subtract(config.getDefaultServerDhModulus());
                    config.setDefaultServerDhPublicKey(pubShare);
                    break;
            }
        }
    }

}
