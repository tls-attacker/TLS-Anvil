/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.model;

import de.rub.nds.tlstest.framework.model.derivationParameter.BasicDerivationType;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.constants.TestEndpointType;
import de.rub.nds.tlstest.framework.model.constraint.ConditionalConstraint;
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
 * Provides a model for Coffee4j or a SimpleTlsTest
 */
public class ParameterModelFactory {

    public static InputParameterModel generateModel(DerivationScope derivationScope, TestContext testContext) {
        List<DerivationType> derivationTypes = getDerivationsForScope(derivationScope);
        Parameter.Builder[] builders = getModelParameters(derivationTypes, testContext, derivationScope);
        Constraint[] constraints = getModelConstraints(derivationTypes, derivationScope);

        return inputParameterModel("dynamic-model").strength(derivationScope.getTestStrength()).parameters(builders).exclusionConstraints(constraints).build();
    }

    public static List<DerivationType> getDerivationsForScope(DerivationScope derivationScope) {
        List<DerivationType> resultingDerivations = new LinkedList<>();
        List<DerivationType> derivationsOfModel = getDerivationsOfModel(derivationScope);
        for (DerivationType derivationType : DerivationManager.getInstance().getAllDerivations()) {
            if (!isBeyondScope(derivationType, derivationsOfModel, derivationScope.getScopeLimits(), derivationScope.getScopeExtensions())) {
                resultingDerivations.add(derivationType);
            }
        }

        return resultingDerivations;
    }

    private static List<DerivationType> getDerivationsOfModel(DerivationScope derivationScope) {
        return getDerivationsOfModel(derivationScope, derivationScope.getBaseModel());
    }

    private static List<DerivationType> getDerivationsOfModel(DerivationScope derivationScope, ModelType baseModel) {
        return DerivationManager.getInstance().getDerivationsOfModel(derivationScope, baseModel);
    }

    private static Parameter.Builder[] getModelParameters(List<DerivationType> derivationTypes, TestContext testContext, DerivationScope derivationScope) {
        List<Parameter.Builder> parameterBuilders = new LinkedList<>();
        for (DerivationType derivationType : derivationTypes) {
            DerivationParameter paramDerivation = DerivationManager.getInstance().getDerivationParameterInstance(derivationType);
            if (paramDerivation.canBeModeled(testContext, derivationScope)) {
                parameterBuilders.add(paramDerivation.getParameterBuilder(testContext, derivationScope));
                if (derivationType.isBitmaskDerivation()) {
                    DerivationParameter bitPositionParam = DerivationManager.getInstance().getDerivationParameterInstance(BasicDerivationType.BIT_POSITION);
                    bitPositionParam.setParent(derivationType);
                    parameterBuilders.add(bitPositionParam.getParameterBuilder(testContext, derivationScope));
                }
            }
        }

        return parameterBuilders.toArray(new Parameter.Builder[]{});
    }

    private static Constraint[] getModelConstraints(List<DerivationType> derivationTypes, DerivationScope scope) {
        List<Constraint> applicableConstraints = new LinkedList<>();
        for (DerivationType derivationType : derivationTypes) {
            if (DerivationManager.getInstance().getDerivationParameterInstance(derivationType).canBeModeled(TestContext.getInstance(), scope)) {
                List<ConditionalConstraint> condConstraints = DerivationManager.getInstance().getDerivationParameterInstance(derivationType).getConditionalConstraints(scope);
                for (ConditionalConstraint condConstraint : condConstraints) {
                    if (condConstraint.isApplicableTo(derivationTypes, scope)) {
                        applicableConstraints.add(condConstraint.getConstraint());
                    }
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

    /**
     * DerivationParameters that only have one possible value can not be modeled
     * by Coffee4J, we collect these here with their static value so the config
     * can be set up properly
     */
    public static List<DerivationParameter> getStaticParameters(TestContext context, DerivationScope scope) {
        List<DerivationParameter> staticParameters = new LinkedList<>();
        List<DerivationType> plannedDerivations = getDerivationsForScope(scope);
        for (DerivationType type : plannedDerivations) {
            List<DerivationParameter> parameterValues = DerivationManager.getInstance().getDerivationParameterInstance(type).getConstrainedParameterValues(context, scope);
            if (parameterValues.size() == 1) {
                staticParameters.add(parameterValues.get(0));
            }
        }
        return staticParameters;
    }

    public static boolean mustUseSimpleModel(TestContext context, DerivationScope scope) {
        List<DerivationType> derivationTypes = getDerivationsForScope(scope);
        Parameter.Builder[] builders = getModelParameters(derivationTypes, context, scope);
        return builders.length == 1;
    }

    public static List<DerivationParameter> getSimpleModelVariations(TestContext context, DerivationScope scope) {
        List<DerivationType> modelDerivations = getDerivationsForScope(scope);
        for (DerivationType type : modelDerivations) {
            DerivationParameter parameter = DerivationManager.getInstance().getDerivationParameterInstance(type);
            if (parameter.canBeModeled(context, scope)) {
                return parameter.getConstrainedParameterValues(context, scope);
            }
        }
        return null;
    }
}
