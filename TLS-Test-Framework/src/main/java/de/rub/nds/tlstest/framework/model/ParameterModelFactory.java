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

import de.rub.nds.tlstest.framework.model.derivationParameter.DerivationFactory;
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

    private static final Logger LOGGER = LogManager.getLogger();

    public static InputParameterModel generateModel(DerivationScope derivationScope, TestContext testContext) {
        List<DerivationType> derivationTypes = getDerivationsForScope(derivationScope);
        Parameter.Builder[] builders = getModelParameters(derivationTypes, testContext, derivationScope);
        Constraint[] constraints = getModelConstraints(derivationTypes, derivationScope);

        return inputParameterModel("dynamic-model").strength(2).parameters(builders).exclusionConstraints(constraints).build();
    }

    public static List<DerivationType> getDerivationsForScope(DerivationScope derivationScope) {
        List<DerivationType> resultingDerivations = new LinkedList<>();
        List<DerivationType> derivationsOfModel = getDerivationsOfModel(derivationScope);
        for (DerivationType derivationType : DerivationType.values()) {
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
        LinkedList<DerivationType> derivationsOfModel = new LinkedList<>();
        switch (baseModel) {
            case EMPTY:
                break;
            case LENGTHFIELD:
                List<DerivationType> lengthfieldDerivations = getDerivationsOfModel(derivationScope, ModelType.CERTIFICATE);
                lengthfieldDerivations.remove(DerivationType.RECORD_LENGTH);
                lengthfieldDerivations.remove(DerivationType.TCP_FRAGMENTATION);
                return lengthfieldDerivations;
            case CERTIFICATE:
                if (TestContext.getInstance().getConfig().getTestEndpointMode() == TestEndpointType.CLIENT) {
                    derivationsOfModel.add(DerivationType.CERTIFICATE);
                    derivationsOfModel.add(DerivationType.SIG_HASH_ALGORIHTM);
                }
            case GENERIC:
            default:
                derivationsOfModel.addAll(getBasicModelDerivations(derivationScope));
        }
        return derivationsOfModel;
    }

    private static Parameter.Builder[] getModelParameters(List<DerivationType> derivationTypes, TestContext testContext, DerivationScope derivationScope) {
        List<Parameter.Builder> parameterBuilders = new LinkedList<>();
        for (DerivationType derivationType : derivationTypes) {
            DerivationParameter paramDerivation = DerivationFactory.getInstance(derivationType);
            if (paramDerivation.canBeModeled(testContext, derivationScope)) {
                parameterBuilders.add(paramDerivation.getParameterBuilder(testContext, derivationScope));
                if (derivationType.isBitmaskDerivation()) {
                    DerivationParameter bitPositionParam = DerivationFactory.getInstance(DerivationType.BIT_POSITION);
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
            if (DerivationFactory.getInstance(derivationType).canBeModeled(TestContext.getInstance(), scope)) {
                List<ConditionalConstraint> condConstraints = DerivationFactory.getInstance(derivationType).getConditionalConstraints(scope);
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

    private static List<DerivationType> getBasicModelDerivations(DerivationScope derivationScope) {
        List<DerivationType> derivationTypes = new LinkedList<>();
        derivationTypes.add(DerivationType.CIPHERSUITE);
        derivationTypes.add(DerivationType.NAMED_GROUP);
        derivationTypes.add(DerivationType.RECORD_LENGTH);
        derivationTypes.add(DerivationType.TCP_FRAGMENTATION);

        if (derivationScope.isTls13Test()) {
            derivationTypes.add(DerivationType.INCLUDE_CHANGE_CIPHER_SPEC);
        }

        List<ExtensionType> supportedExtensions = TestContext.getInstance().getSiteReport().getSupportedExtensions();
        if (TestContext.getInstance().getConfig().getTestEndpointMode() == TestEndpointType.SERVER
                && TestContext.getInstance().getSiteReport().getSupportedExtensions() != null) {
            //we add all extension regardless if the server negotiates them
            derivationTypes.add(DerivationType.INCLUDE_ALPN_EXTENSION);
            derivationTypes.add(DerivationType.INCLUDE_HEARTBEAT_EXTENSION);
            derivationTypes.add(DerivationType.INCLUDE_PADDING_EXTENSION);
            derivationTypes.add(DerivationType.INCLUDE_RENEGOTIATION_EXTENSION);
            derivationTypes.add(DerivationType.INCLUDE_EXTENDED_MASTER_SECRET_EXTENSION);
            
            //we must know if the server negotiates Encrypt-Then-Mac to be able
            //to define correct constraints for padding tests
            if (supportedExtensions.contains(ExtensionType.ENCRYPT_THEN_MAC)) {
                derivationTypes.add(DerivationType.INCLUDE_ENCRYPT_THEN_MAC_EXTENSION);
            }
            
            if (derivationScope.isTls13Test()) {
                derivationTypes.add(DerivationType.INCLUDE_PSK_EXCHANGE_MODES_EXTENSION);
            }
        }
        
        if(TestContext.getInstance().getConfig().getTestEndpointMode() == TestEndpointType.SERVER 
                && TestContext.getInstance().getSiteReport().getResult(AnalyzedProperty.TOLERATES_GREASE_CIPHER_SUITE) == TestResult.TRUE) {
            derivationTypes.add(DerivationType.INCLUDE_GREASE_CIPHER_SUITES);
        }
        
        if(TestContext.getInstance().getConfig().getTestEndpointMode() == TestEndpointType.SERVER 
                && TestContext.getInstance().getSiteReport().getResult(AnalyzedProperty.TOLERATES_GREASE_NAMED_GROUP) == TestResult.TRUE) {
            derivationTypes.add(DerivationType.INCLUDE_GREASE_NAMED_GROUPS);
        }
        
        if(TestContext.getInstance().getConfig().getTestEndpointMode() == TestEndpointType.SERVER 
                && TestContext.getInstance().getSiteReport().getResult(AnalyzedProperty.TOLERATES_GREASE_SIGNATURE_AND_HASH_ALGORITHM) == TestResult.TRUE) {
            derivationTypes.add(DerivationType.INCLUDE_GREASE_SIG_HASH_ALGORITHMS);
        }
        
        return derivationTypes;
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
            List<DerivationParameter> parameterValues = DerivationFactory.getInstance(type).getConstrainedParameterValues(context, scope);
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
            DerivationParameter parameter = DerivationFactory.getInstance(type);
            if (parameter.canBeModeled(context, scope)) {
                return parameter.getConstrainedParameterValues(context, scope);
            }
        }
        return null;
    }
}
