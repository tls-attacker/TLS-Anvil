/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlstest.framework.model.constraint;

import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.model.DerivationManager;
import de.rub.nds.tlstest.framework.model.DerivationScope;
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rwth.swc.coffee4j.model.constraints.Constraint;
import java.util.List;
import java.util.Set;

public class ConditionalConstraint {
    private final Set<DerivationType> requiredDerivations;
    private final Constraint constraint;

    public Set<DerivationType> getRequiredDerivations() {
        return requiredDerivations;
    }

    public Constraint getConstraint() {
        return constraint;
    }
    
    public boolean isApplicableTo(List<DerivationType> modeledDerivations, DerivationScope scope) {
        for(DerivationType required: requiredDerivations) {
            if(!modeledDerivations.contains(required) || !DerivationManager.getInstance().getDerivationParameterInstance(required).canBeModeled(TestContext.getInstance(), scope)) {
                return false;
            }
        }
        return true;
    }

    public ConditionalConstraint(Set<DerivationType> requiredDerivations, Constraint constraint) {
        this.requiredDerivations = requiredDerivations;
        this.constraint = constraint;
    }
    
    
}
