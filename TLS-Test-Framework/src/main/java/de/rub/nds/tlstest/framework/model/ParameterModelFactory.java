/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.model;

import static de.rwth.swc.coffee4j.model.InputParameterModel.inputParameterModel;

import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.ModelType;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlstest.framework.ClientFeatureExtractionResult;
import de.rub.nds.tlstest.framework.ServerFeatureExtractionResult;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.constants.TestEndpointType;
import de.rub.nds.tlstest.framework.model.constraint.ConstraintHelper;
import de.rub.nds.tlstest.framework.model.constraint.LegacyConditionalConstraint;
import de.rub.nds.tlstest.framework.model.derivationParameter.DerivationFactory;
import de.rwth.swc.coffee4j.model.InputParameterModel;
import de.rwth.swc.coffee4j.model.Parameter;
import de.rwth.swc.coffee4j.model.constraints.Constraint;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** Provides a model for Coffee4j or a SimpleTlsTest */
public class ParameterModelFactory {

    private static final Logger LOGGER = LogManager.getLogger();

    public static InputParameterModel generateModel(
            DerivationScope derivationScope, TestContext testContext) {
        List<TlsParameterType> derivationTypes = getDerivationsForScope(derivationScope);
        Parameter.Builder[] builders =
                getModelParameters(derivationTypes, testContext, derivationScope);
        Constraint[] constraints = getModelConstraints(derivationTypes, derivationScope);

        return inputParameterModel("dynamic-model")
                .strength(derivationScope.getTestStrength())
                .parameters(builders)
                .exclusionConstraints(constraints)
                .build();
    }

    public static List<TlsParameterType> getDerivationsForScope(DerivationScope derivationScope) {
        List<TlsParameterType> resultingDerivations = new LinkedList<>();
        List<TlsParameterType> derivationsOfModel = getDerivationsOfModel(derivationScope);
        for (TlsParameterType derivationType : TlsParameterType.values()) {
            if (!isBeyondScope(
                    derivationType,
                    derivationsOfModel,
                    derivationScope.getIpmLimitations(),
                    derivationScope.getIpmExtensions())) {
                resultingDerivations.add(derivationType);
            }
        }

        return resultingDerivations;
    }

    private static List<TlsParameterType> getDerivationsOfModel(DerivationScope derivationScope) {
        return getDerivationsOfModel(derivationScope, derivationScope.getModelType());
    }

    private static List<TlsParameterType> getDerivationsOfModel(
            DerivationScope derivationScope, ModelType baseModel) {
        LinkedList<TlsParameterType> derivationsOfModel = new LinkedList<>();
        switch ((TlsModelType) baseModel) {
            case EMPTY:
                break;
            case LENGTHFIELD:
            case CERTIFICATE:
                if (TestContext.getInstance().getConfig().getTestEndpointMode()
                        == TestEndpointType.CLIENT) {
                    derivationsOfModel.add(TlsParameterType.CERTIFICATE);
                    derivationsOfModel.add(TlsParameterType.SIG_HASH_ALGORIHTM);
                }
            case GENERIC:
            default:
                derivationsOfModel.addAll(getBasicModelDerivations(derivationScope));
        }
        return derivationsOfModel;
    }

    private static Parameter.Builder[] getModelParameters(
            List<TlsParameterType> derivationTypes,
            TestContext testContext,
            DerivationScope derivationScope) {
        List<Parameter.Builder> parameterBuilders = new LinkedList<>();
        for (TlsParameterType derivationType : derivationTypes) {
            DerivationParameter paramDerivation = DerivationFactory.getInstance(derivationType);
            if (paramDerivation.canBeModeled(derivationScope)) {
                parameterBuilders.add(paramDerivation.getParameterBuilder(derivationScope));
                if (derivationType.isBitmaskDerivation()) {
                    DerivationParameter bitPositionParam =
                            DerivationFactory.getInstance(TlsParameterType.BIT_POSITION);
                    // bitPositionParam.setParent(derivationType);
                    parameterBuilders.add(bitPositionParam.getParameterBuilder(derivationScope));
                }
            }
        }

        return parameterBuilders.toArray(new Parameter.Builder[] {});
    }

    private static Constraint[] getModelConstraints(
            List<TlsParameterType> derivationTypes, DerivationScope scope) {
        List<Constraint> applicableConstraints = new LinkedList<>();
        for (TlsParameterType derivationType : derivationTypes) {
            if (DerivationFactory.getInstance(derivationType).canBeModeled(scope)) {
                List<LegacyConditionalConstraint> condConstraints =
                        DerivationFactory.getInstance(derivationType)
                                .getConditionalConstraints(scope);
                for (LegacyConditionalConstraint condConstraint : condConstraints) {
                    if (condConstraint.isApplicableTo(derivationTypes, scope)) {
                        applicableConstraints.add(condConstraint.getConstraint());
                    }
                }
            }
        }

        return applicableConstraints.toArray(new Constraint[] {});
    }

    private static boolean isBeyondScope(
            TlsParameterType derivationParameter,
            List<TlsParameterType> basicDerivations,
            List<ParameterIdentifier> scopeLimitations,
            List<ParameterIdentifier> scopeExtensions) {
        if ((!basicDerivations.contains(derivationParameter)
                        && !scopeExtensions.contains(derivationParameter))
                || scopeLimitations.contains(derivationParameter)) {
            return true;
        }
        return false;
    }

    private static List<TlsParameterType> getBasicModelDerivations(
            DerivationScope derivationScope) {
        List<TlsParameterType> derivationTypes = getBasicDerivationsForBoth(derivationScope);

        if (TestContext.getInstance().getConfig().getTestEndpointMode()
                == TestEndpointType.SERVER) {
            derivationTypes.addAll(getBasicDerivationsForServer(derivationScope));
        } else {
            derivationTypes.addAll(getBasicDerivationsForClient(derivationScope));
        }
        return derivationTypes;
    }

    private static List<TlsParameterType> getBasicDerivationsForBoth(
            DerivationScope derivationScope) {
        List<TlsParameterType> derivationTypes = new LinkedList<>();
        derivationTypes.add(TlsParameterType.CIPHER_SUITE);
        derivationTypes.add(TlsParameterType.NAMED_GROUP);
        derivationTypes.add(TlsParameterType.RECORD_LENGTH);
        derivationTypes.add(TlsParameterType.TCP_FRAGMENTATION);

        if (ConstraintHelper.isTls13Test(derivationScope)) {
            derivationTypes.add(TlsParameterType.INCLUDE_CHANGE_CIPHER_SPEC);
        }

        return derivationTypes;
    }

    private static List<TlsParameterType> getBasicDerivationsForServer(
            DerivationScope derivationScope) {
        List<TlsParameterType> derivationTypes = new LinkedList<>();
        Set<ExtensionType> supportedExtensions =
                ((ServerFeatureExtractionResult)
                                TestContext.getInstance().getFeatureExtractionResult())
                        .getNegotiableExtensions();
        if (supportedExtensions != null) {
            // we add all extension regardless if the server negotiates them
            derivationTypes.add(TlsParameterType.INCLUDE_ALPN_EXTENSION);
            derivationTypes.add(TlsParameterType.INCLUDE_HEARTBEAT_EXTENSION);
            derivationTypes.add(TlsParameterType.INCLUDE_PADDING_EXTENSION);
            derivationTypes.add(TlsParameterType.INCLUDE_RENEGOTIATION_EXTENSION);
            derivationTypes.add(TlsParameterType.INCLUDE_EXTENDED_MASTER_SECRET_EXTENSION);
            derivationTypes.add(TlsParameterType.INCLUDE_SESSION_TICKET_EXTENSION);
            derivationTypes.add(TlsParameterType.MAX_FRAGMENT_LENGTH);

            // we must know if the server negotiates Encrypt-Then-Mac to be able
            // to define correct constraints for padding tests
            if (supportedExtensions.contains(ExtensionType.ENCRYPT_THEN_MAC)) {
                derivationTypes.add(TlsParameterType.INCLUDE_ENCRYPT_THEN_MAC_EXTENSION);
            }

            if (ConstraintHelper.isTls13Test(derivationScope)) {
                derivationTypes.add(TlsParameterType.INCLUDE_PSK_EXCHANGE_MODES_EXTENSION);
            }
        }

        if (TestContext.getInstance()
                        .getFeatureExtractionResult()
                        .getResult(TlsAnalyzedProperty.HAS_GREASE_CIPHER_SUITE_INTOLERANCE)
                != TestResults.TRUE) {
            derivationTypes.add(TlsParameterType.INCLUDE_GREASE_CIPHER_SUITES);
        }

        if (TestContext.getInstance()
                        .getFeatureExtractionResult()
                        .getResult(TlsAnalyzedProperty.HAS_GREASE_NAMED_GROUP_INTOLERANCE)
                != TestResults.TRUE) {
            derivationTypes.add(TlsParameterType.INCLUDE_GREASE_NAMED_GROUPS);
        }

        if (TestContext.getInstance()
                        .getFeatureExtractionResult()
                        .getResult(
                                TlsAnalyzedProperty
                                        .HAS_GREASE_SIGNATURE_AND_HASH_ALGORITHM_INTOLERANCE)
                != TestResults.TRUE) {
            derivationTypes.add(TlsParameterType.INCLUDE_GREASE_SIG_HASH_ALGORITHMS);
        }
        return derivationTypes;
    }

    private static List<TlsParameterType> getBasicDerivationsForClient(
            DerivationScope derivationScope) {
        List<TlsParameterType> derivationTypes = new LinkedList<>();
        ClientFeatureExtractionResult extractionResult =
                (ClientFeatureExtractionResult)
                        TestContext.getInstance().getFeatureExtractionResult();
        if (!ConstraintHelper.isTls13Test(derivationScope)) {

            if (extractionResult
                    .getReceivedClientHello()
                    .containsExtension(ExtensionType.ENCRYPT_THEN_MAC)) {
                derivationTypes.add(TlsParameterType.INCLUDE_ENCRYPT_THEN_MAC_EXTENSION);
            }

            if (extractionResult
                    .getReceivedClientHello()
                    .containsExtension(ExtensionType.EXTENDED_MASTER_SECRET)) {
                derivationTypes.add(TlsParameterType.INCLUDE_EXTENDED_MASTER_SECRET_EXTENSION);
            }
        }
        return derivationTypes;
    }

    /**
     * DerivationParameters that only have one possible value can not be modeled by Coffee4J, we
     * collect these here with their static value so the config can be set up properly
     */
    public static List<DerivationParameter> getStaticParameters(
            TestContext context, DerivationScope scope) {
        List<DerivationParameter> staticParameters = new LinkedList<>();
        List<TlsParameterType> plannedDerivations = getDerivationsForScope(scope);
        for (TlsParameterType type : plannedDerivations) {
            List<DerivationParameter> parameterValues =
                    DerivationFactory.getInstance(type).getConstrainedParameterValues(scope);
            if (parameterValues.size() == 1) {
                staticParameters.add(parameterValues.get(0));
            }
        }
        return staticParameters;
    }

    public static boolean mustUseSimpleModel(TestContext context, DerivationScope scope) {
        List<TlsParameterType> derivationTypes = getDerivationsForScope(scope);
        Parameter.Builder[] builders = getModelParameters(derivationTypes, context, scope);
        return builders.length == 1;
    }

    public static List<DerivationParameter> getSimpleModelVariations(
            TestContext context, DerivationScope scope) {
        List<TlsParameterType> modelDerivations = getDerivationsForScope(scope);
        for (TlsParameterType type : modelDerivations) {
            DerivationParameter parameter = DerivationFactory.getInstance(type);
            if (parameter.canBeModeled(scope)) {
                return parameter.getConstrainedParameterValues(scope);
            }
        }
        return null;
    }
}
