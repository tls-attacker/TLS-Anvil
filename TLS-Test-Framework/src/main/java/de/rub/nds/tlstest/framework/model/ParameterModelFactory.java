/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlstest.framework.model;


import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.model.constraint.ConditionalConstraint;
import de.rub.nds.tlstest.framework.model.derivationParameter.DerivationInstanceFactory;
import de.rub.nds.tlstest.framework.model.derivationParameter.DerivationParameter;
import de.rwth.swc.coffee4j.model.InputParameterModel;
import static de.rwth.swc.coffee4j.model.InputParameterModel.inputParameterModel;
import de.rwth.swc.coffee4j.model.Parameter;
import de.rwth.swc.coffee4j.model.constraints.Constraint;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author marcel
 */
public class ParameterModelFactory {

    private static final Logger LOGGER = LogManager.getLogger();

    public static InputParameterModel generateModel(DerivationScope derivationScope, TestContext testContext) {
        List<DerivationType> derivationTypes = getDerivationsForScope(derivationScope);
        Parameter.Builder[] builders  = getModelParameters(derivationTypes, testContext, derivationScope);
        Constraint[] constraints = getModelConstraints(derivationTypes);

        
        return inputParameterModel("dynamic-model").strength(2).parameters(builders).exclusionConstraints(constraints).build();
    }

    private static List<DerivationType> getDerivationsForScope(DerivationScope derivationScope) {
        List<DerivationType> resultingDerivations = new LinkedList<>();
        List<DerivationType> derivationsOfModel = getDerivationsOfModel(derivationScope.getBaseModel());
        for (DerivationType derivationType : DerivationType.values()) {
            if (!isBeyondScope(derivationType, derivationsOfModel, derivationScope.getScopeLimits(), derivationScope.getScopeExtensions())) {
                resultingDerivations.add(derivationType);
            }
        }

        return resultingDerivations;
    }

    private static List<DerivationType> getDerivationsOfModel(ModelType baseModel) {
        switch (baseModel) {
            case EMPTY:
                return new LinkedList<>();
            case GENERIC:
            default:
                return getBasicModelDerivations();
        }
    }

    private static Parameter.Builder[] getModelParameters(List<DerivationType> derivationTypes, TestContext testContext, DerivationScope derivationScope) {
        List<Parameter.Builder> parameterBuilders = new LinkedList<>();
        for (DerivationType derivationType : derivationTypes) {
            DerivationParameter paramDerivation = DerivationInstanceFactory.getInstance(derivationType);
            parameterBuilders.add(paramDerivation.getParameterBuilder(testContext, derivationScope));
        }

        return parameterBuilders.toArray(new Parameter.Builder[]{});
    }
    
    private static Constraint[] getModelConstraints(List<DerivationType> derivationTypes) {
        List<Constraint> applicableConstraints = new LinkedList<>();
        for (DerivationType derivationType : derivationTypes) {
            List<ConditionalConstraint> condConstraints = DerivationInstanceFactory.getInstance(derivationType).getConditionalConstraints();
            for(ConditionalConstraint condConstraint : condConstraints) {
                if(condConstraint.isApplicableTo(derivationTypes)) {
                    applicableConstraints.add(condConstraint.getConstraint());
                }
            }
        }
        
        return applicableConstraints.toArray(new Constraint[]{});
    }


    private static boolean isBeyondScope(DerivationType derivationParameter, List<DerivationType> basicDerivations, List<DerivationType> scopeLimitations, List<DerivationType> scopeExtensions) {
        if ((!basicDerivations.contains(derivationParameter) && !scopeExtensions.contains(derivationParameter)) || scopeLimitations.contains(derivationParameter)) {
            return true;
        }
        return false;
    }

    private static List<DerivationType> getBasicModelDerivations() {
        List<DerivationType> derivationTypes = new LinkedList<>();
        derivationTypes.add(DerivationType.CIPHERSUITE);
        derivationTypes.add(DerivationType.NAMED_GROUP);
        derivationTypes.add(DerivationType.MAC_BITMASK);
        derivationTypes.add(DerivationType.ALERT);
        return derivationTypes;
    }
}
