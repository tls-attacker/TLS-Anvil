package de.rub.nds.tlstest.framework.model.derivationParameter.mirrored;

import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.model.DerivationManager;
import de.rub.nds.tlstest.framework.model.DerivationScope;
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.model.constraint.ConditionalConstraint;
import de.rub.nds.tlstest.framework.model.derivationParameter.*;
import de.rwth.swc.coffee4j.model.constraints.ConstraintBuilder;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

/**
 *
 */
public class MirroredCipherSuiteDerivation extends MirroredDerivationParameter<CipherSuite> {

    public MirroredCipherSuiteDerivation() {
        super(BasicDerivationType.MIRRORED_CIPHERSUITE, BasicDerivationType.CIPHERSUITE, CipherSuite.class);
    }
    
    public MirroredCipherSuiteDerivation(CipherSuite selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }
    
    @Override
    public List<DerivationParameter> getParameterValues(TestContext context, DerivationScope scope) {
        List<DerivationParameter> parameterValues = new LinkedList<>();
        DerivationManager.getInstance().getDerivationParameterInstance(getMirroredType()).getParameterValues(context, scope)
                .forEach(derivation -> parameterValues.add(new MirroredCipherSuiteDerivation(((CipherSuiteDerivation)(derivation)).getSelectedValue())));
        return parameterValues;
    }

    @Override
    public List<ConditionalConstraint> getDefaultConditionalConstraints(DerivationScope scope) {
        List<ConditionalConstraint> condConstraints = new LinkedList<>();
        Set<DerivationType> requiredDerivations = new HashSet<>();
        requiredDerivations.add(BasicDerivationType.CIPHERSUITE);
        condConstraints.add(new ConditionalConstraint(requiredDerivations, ConstraintBuilder.constrain(getType().toString(), BasicDerivationType.CIPHERSUITE.name()).by((DerivationParameter mirroredCipherSuite, DerivationParameter cipherSuite) -> {
            if (mirroredCipherSuite.getSelectedValue().equals(cipherSuite.getSelectedValue())) {
                return false;
            }
            return true;
        })));

        return condConstraints;
    }

}
