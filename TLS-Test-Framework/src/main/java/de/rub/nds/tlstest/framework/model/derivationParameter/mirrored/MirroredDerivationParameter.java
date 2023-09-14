/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.model.derivationParameter.mirrored;

import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.parameter.ParameterScope;
import de.rub.nds.tlstest.framework.anvil.TlsDerivationParameter;
import de.rub.nds.tlstest.framework.model.TlsParameterType;

/**
 * Provides the same values overall as its mirrored type. This should be used when tests require
 * each possible value of a derivation parameter twice but only as long as they are not identical
 * within a test combination (e.g of a set A,B,C the combination (A,A) (B,B) (C,C) are forbidden)
 */
public abstract class MirroredDerivationParameter<T> extends TlsDerivationParameter<T> {

    private final TlsParameterType mirroredType;

    public MirroredDerivationParameter(
            TlsParameterType type, TlsParameterType mirroredType, Class<T> valueClass) {
        super(type, valueClass);
        this.mirroredType = mirroredType;
    }

    @Override
    public boolean hasNoApplicableValues(DerivationScope scope) {
        return getMirroredType().getInstance(ParameterScope.NO_SCOPE).hasNoApplicableValues(scope);
    }

    @Override
    public boolean canBeModeled(DerivationScope scope) {
        return getMirroredType().getInstance(ParameterScope.NO_SCOPE).canBeModeled(scope);
    }

    public TlsParameterType getMirroredType() {
        return mirroredType;
    }
}
