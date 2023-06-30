/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlstest.framework.model.constraint;

import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.model.LegacyDerivationScope;
import de.rub.nds.tlstest.framework.model.TlsParameterType;
import de.rub.nds.tlstest.framework.model.derivationParameter.DerivationFactory;
import de.rwth.swc.coffee4j.model.constraints.Constraint;
import java.util.List;
import java.util.Set;

public class LegacyConditionalConstraint {
    private final Set<TlsParameterType> requiredDerivations;
    private final Constraint constraint;

    public Set<TlsParameterType> getRequiredDerivations() {
        return requiredDerivations;
    }

    public Constraint getConstraint() {
        return constraint;
    }

    public boolean isApplicableTo(List<TlsParameterType> modeledDerivations, LegacyDerivationScope scope) {
        for (TlsParameterType required : requiredDerivations) {
            if (!modeledDerivations.contains(required)
                    || !DerivationFactory.getInstance(required)
                            .canBeModeled(TestContext.getInstance(), scope)) {
                return false;
            }
        }
        return true;
    }

    public LegacyConditionalConstraint(Set<TlsParameterType> requiredDerivations, Constraint constraint) {
        this.requiredDerivations = requiredDerivations;
        this.constraint = constraint;
    }
}
