package de.rub.nds.tlstest.framework.model.derivationParameter.mirrored;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.model.DerivationScope;
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.model.derivationParameter.DerivationFactory;
import de.rub.nds.tlstest.framework.model.derivationParameter.DerivationParameter;


/**
 * Provides the same values overall as it's mirrored type. This should be used
 * when tests require each possible value of a derivation parameter twice but
 * only as long as they are not identical within a test combination (e.g of a
 * set A,B,C the combination (A,A) (B,B) (C,C) are forbidden)
 */
public abstract class MirroredDerivationParameter<T> extends DerivationParameter<T> {
    
    private final DerivationType mirroredType;

    public MirroredDerivationParameter(DerivationType type, DerivationType mirroredType, Class<T> valueClass) {
        super(type, valueClass);
        this.mirroredType = mirroredType;
    }

    @Override
    public void applyToConfig(Config config, TestContext context) {
    }

    @Override
    public boolean hasNoApplicableValues(TestContext context, DerivationScope scope) {
        return DerivationFactory.getInstance(getMirroredType()).hasNoApplicableValues(context, scope);
    }

    @Override
    public boolean canBeModeled(TestContext context, DerivationScope scope) {
        return DerivationFactory.getInstance(getMirroredType()).canBeModeled(context, scope);
    }     

    public DerivationType getMirroredType() {
        return mirroredType;
    }
    
}
