package de.rub.nds.tlstest.framework.anvil;

import static de.rub.nds.tlstest.framework.anvil.TlsModelTypes.*;
import static de.rub.nds.tlstest.framework.model.TlsParameterType.BIT_POSITION;

import de.rub.nds.anvilcore.constants.TestEndpointType;
import de.rub.nds.anvilcore.model.DefaultModelTypes;
import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.ParameterIdentifierProvider;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlstest.framework.ClientFeatureExtractionResult;
import de.rub.nds.tlstest.framework.ServerFeatureExtractionResult;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.model.TlsParameterType;
import de.rub.nds.tlstest.framework.model.constraint.ConstraintHelper;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public class TlsParameterIdentifierProvider extends ParameterIdentifierProvider {

    /**
     * Creates a list of all possible ParameterIdentifiers. For every normal DerivationType there
     * will be one Identifier. For every BITMASK DerivationTypes, a second BIT_POSITION Identifier
     * will be added.
     *
     * @return all known ParameterIdentifiers
     */
    @Override
    public List<ParameterIdentifier> generateAllParameterIdentifiers() {
        List<ParameterIdentifier> identifiers = new LinkedList<>();
        for (TlsParameterType listed : TlsParameterType.values()) {
            if (listed != BIT_POSITION) {
                ParameterIdentifier identifierToAdd = new ParameterIdentifier(listed);
                identifiers.add(identifierToAdd);
                if (listed.isBitmaskDerivation()) {
                    ParameterIdentifier linkedIdentifier =
                            new ParameterIdentifier(
                                    BIT_POSITION, new BitPositionParameterScope(listed));
                    identifierToAdd.setLinkedParameterIdentifier(linkedIdentifier);
                    identifiers.add(linkedIdentifier);
                }
            }
        }
        return identifiers;
    }

    @Override
    public List<ParameterIdentifier> getModelParameterIdentifiers(DerivationScope derivationScope) {
        String modelType = derivationScope.getModelType();
        if (TlsModelTypes.tlsModelTypes.contains(modelType)) {
            return getDerivationsOfModel(derivationScope, modelType).stream()
                    .map(ParameterIdentifier::new)
                    .collect(Collectors.toList());
        }
        return super.getModelParameterIdentifiers(derivationScope);
    }

    private static List<TlsParameterType> getDerivationsOfModel(
            DerivationScope derivationScope, String baseModel) {
        LinkedList<TlsParameterType> derivationsOfModel = new LinkedList<>();
        switch (baseModel) {
            case DefaultModelTypes.EMPTY:
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
        if (!TestContext.getInstance().getConfig().isUseDTLS()) {
            derivationTypes.add(TlsParameterType.TCP_FRAGMENTATION);
        }

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
        if (TestContext.getInstance().getConfig().isUseDTLS()) {
            derivationTypes.add(TlsParameterType.COOKIE_EXCHANGE);
        }
        return derivationTypes;
    }
}
