/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.model.derivationParameter;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.constants.TestEndpointType;
import de.rub.nds.tlstest.framework.model.DerivationCategoryManager;
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.model.DerivationScope;
import de.rub.nds.tlstest.framework.model.ModelType;
import de.rub.nds.tlstest.framework.model.derivationParameter.keyexchange.dhe.ShareOutOfBoundsDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.mirrored.MirroredCipherSuiteDerivation;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.LinkedList;
import java.util.List;

/**
 * The DerivationCategoryManager responsible for the BasicDerivationType.
 */
public class BasicDerivationManager implements DerivationCategoryManager{
    private static BasicDerivationManager instance = null;
    private static final Logger LOGGER = LogManager.getLogger();

    public static synchronized BasicDerivationManager getInstance() {
        if (BasicDerivationManager.instance == null) {
            BasicDerivationManager.instance = new BasicDerivationManager();
        }
        return BasicDerivationManager.instance;
    }

    private BasicDerivationManager() {

    }

    public DerivationParameter getDerivationParameterInstance(DerivationType type)
    {
        if(!(type instanceof BasicDerivationType)){
            throw new IllegalArgumentException("This manager can only handle BasicDerivationTypes but type '"+type+"' was passed.");
        }
        BasicDerivationType basicType = (BasicDerivationType) type;
        switch(basicType) {
            case CIPHERSUITE:
                return new CipherSuiteDerivation();
            case MAC_BITMASK:
                return new MacBitmaskDerivation();
            case ALERT:
                return new AlertDerivation();
            case NAMED_GROUP:
                return new NamedGroupDerivation();
            case RECORD_LENGTH:
                return new RecordLengthDerivation();
            case TCP_FRAGMENTATION:
                return new TcpFragmentationDerivation();
            case CIPHERTEXT_BITMASK:
                return new CipherTextBitmaskDerivation();
            case AUTH_TAG_BITMASK:
                return new AuthTagBitmaskDerivation();
            case APP_MSG_LENGHT:
                return new AppMsgLengthDerivation();
            case BIT_POSITION:
                return new BitPositionDerivation();
            case PADDING_BITMASK:
                return new PaddingBitmaskDerivation();
            case INVALID_CCS_CONTENT:
                return new InvalidCCSContentDerivation();
            case PRF_BITMASK:
                return new PRFBitmaskDerivation();
            case GREASE_CIPHERSUITE:
                return new GreaseCipherSuiteDerivation();
            case GREASE_EXTENSION:
                return new GreaseExtensionDerivation();
            case GREASE_NAMED_GROUP:
                return new GreaseNamedGroupDerivation();
            case GREASE_PROTOCOL_VERSION:
                return new GreaseProtocolVersionDerivation();
            case GREASE_SIG_HASH:
                return new GreaseSigHashDerivation();
            case PROTOCOL_VERSION:
                return new ProtocolVersionDerivation();
            case SIG_HASH_ALGORIHTM:
                return new SigAndHashDerivation();
            case EXTENSION:
                return new ExtensionDerivation();
            case CHOSEN_HANDSHAKE_MSG:
                return new ChosenHandshakeMessageDerivation();
            case MIRRORED_CIPHERSUITE:
                return new MirroredCipherSuiteDerivation();
            case CERTIFICATE:
                return new CertificateDerivation();
            case SIGNATURE_BITMASK:
                return new SignatureBitmaskDerivation();
            case INCLUDE_ALPN_EXTENSION:
                return new IncludeALPNExtensionDerivation();
            case INCLUDE_CHANGE_CIPHER_SPEC:
                return new IncludeChangeCipherSpecDerivation();
            case INCLUDE_ENCRYPT_THEN_MAC_EXTENSION:
                return new IncludeEncryptThenMacExtensionDerivation();
            case INCLUDE_EXTENDED_MASTER_SECRET_EXTENSION:
                return new IncludeExtendedMasterSecretExtensionDerivation();
            case INCLUDE_HEARTBEAT_EXTENSION:
                return new IncludeHeartbeatExtensionDerivation();
            case INCLUDE_PADDING_EXTENSION:
                return new IncludePaddingExtensionDerivation();
            case INCLUDE_PSK_EXCHANGE_MODES_EXTENSION:
                return new IncludePSKExchangeModesExtensionDerivation();
            case INCLUDE_RENEGOTIATION_EXTENSION:
                return new IncludeRenegotiationExtensionDerivation();
            case INCLUDE_SESSION_TICKET_EXTENSION:
                return new IncludeSessionTicketExtensionDerivation();
            case INCLUDE_GREASE_CIPHER_SUITES:
                return new IncludeGreaseCipherSuitesDerivation();
            case INCLUDE_GREASE_NAMED_GROUPS:
                return new IncludeGreaseNamedGroupsDerivation();
            case INCLUDE_GREASE_SIG_HASH_ALGORITHMS:
                return new IncludeGreaseSigHashDerivation();
            case ADDITIONAL_PADDING_LENGTH:
                return new AdditionalPaddingLengthDerivation();
            case COMPRESSION_METHOD:
                return new CompressionMethodDerivation();
            case PROTOCOL_MESSAGE_TYPE:
                return new ProtocolMessageTypeDerivation();
            case FFDHE_SHARE_OUT_OF_BOUNDS:
                return new ShareOutOfBoundsDerivation();
            case MAX_FRAGMENT_LENGTH:
                return new MaxFragmentLengthDerivation();
            default:
                LOGGER.error("Derivation Type {} not implemented", type);
                throw new UnsupportedOperationException("Derivation Type not implemented");
        }
    }

    public List<DerivationType> getDerivationsOfModel(DerivationScope derivationScope, ModelType baseModel)
    {
        LinkedList<DerivationType> derivationsOfModel = new LinkedList<>();
        switch (baseModel) {
            case EMPTY:
                break;
            case LENGTHFIELD:
            case CERTIFICATE:
                if (TestContext.getInstance().getConfig().getTestEndpointMode() == TestEndpointType.CLIENT) {
                    derivationsOfModel.add(BasicDerivationType.CERTIFICATE);
                    derivationsOfModel.add(BasicDerivationType.SIG_HASH_ALGORIHTM);
                }
            case GENERIC:
            default:
                derivationsOfModel.addAll(getBasicModelDerivations(derivationScope));
        }
        return derivationsOfModel;
    }

    @Override
    public List<DerivationType> getAllDerivations() {
        List<DerivationType> derivationTypes = new LinkedList<>();
        for(BasicDerivationType type : BasicDerivationType.values()){
            derivationTypes.add((DerivationType) type);
        }

        return derivationTypes;
    }

    private static List<DerivationType> getBasicModelDerivations(DerivationScope derivationScope) {
        List<DerivationType> derivationTypes = getBasicDerivationsForBoth(derivationScope);
        
        if(TestContext.getInstance().getConfig().getTestEndpointMode() == TestEndpointType.SERVER) {
            derivationTypes.addAll(getBasicDerivationsForServer(derivationScope));
        } else {
            derivationTypes.addAll(getBasicDerivationsForClient(derivationScope));
        }
        return derivationTypes;
    }
    
    private static List<DerivationType> getBasicDerivationsForBoth(DerivationScope derivationScope) {
        List<DerivationType> derivationTypes = new LinkedList<>();
        derivationTypes.add(BasicDerivationType.CIPHERSUITE);
        derivationTypes.add(BasicDerivationType.NAMED_GROUP);
        derivationTypes.add(BasicDerivationType.RECORD_LENGTH);
        derivationTypes.add(BasicDerivationType.TCP_FRAGMENTATION);

        if (derivationScope.isTls13Test()) {
            derivationTypes.add(BasicDerivationType.INCLUDE_CHANGE_CIPHER_SPEC);
        }
        
        return derivationTypes;
    }
    
    private static List<DerivationType> getBasicDerivationsForServer(DerivationScope derivationScope) {
        List<DerivationType> derivationTypes = new LinkedList<>();
        List<ExtensionType> supportedExtensions = TestContext.getInstance().getSiteReport().getSupportedExtensions();
        if (supportedExtensions != null) {
            //we add all extension regardless if the server negotiates them
            derivationTypes.add(BasicDerivationType.INCLUDE_ALPN_EXTENSION);
            derivationTypes.add(BasicDerivationType.INCLUDE_HEARTBEAT_EXTENSION);
            derivationTypes.add(BasicDerivationType.INCLUDE_PADDING_EXTENSION);
            derivationTypes.add(BasicDerivationType.INCLUDE_RENEGOTIATION_EXTENSION);
            derivationTypes.add(BasicDerivationType.INCLUDE_EXTENDED_MASTER_SECRET_EXTENSION);
            derivationTypes.add(BasicDerivationType.INCLUDE_SESSION_TICKET_EXTENSION);
            derivationTypes.add(BasicDerivationType.MAX_FRAGMENT_LENGTH);
            
            //we must know if the server negotiates Encrypt-Then-Mac to be able
            //to define correct constraints for padding tests
            if (supportedExtensions.contains(ExtensionType.ENCRYPT_THEN_MAC)) {
                derivationTypes.add(BasicDerivationType.INCLUDE_ENCRYPT_THEN_MAC_EXTENSION);
            }
            
            if (derivationScope.isTls13Test()) {
                derivationTypes.add(BasicDerivationType.INCLUDE_PSK_EXCHANGE_MODES_EXTENSION);
            }
        }
        
        if(TestContext.getInstance().getSiteReport().getResult(AnalyzedProperty.HAS_GREASE_CIPHER_SUITE_INTOLERANCE) != TestResult.TRUE) {
            derivationTypes.add(BasicDerivationType.INCLUDE_GREASE_CIPHER_SUITES);
        }
        
        if(TestContext.getInstance().getSiteReport().getResult(AnalyzedProperty.HAS_GREASE_NAMED_GROUP_INTOLERANCE) != TestResult.TRUE) {
            derivationTypes.add(BasicDerivationType.INCLUDE_GREASE_NAMED_GROUPS);
        }
        
        if(TestContext.getInstance().getSiteReport().getResult(AnalyzedProperty.HAS_GREASE_SIGNATURE_AND_HASH_ALGORITHM_INTOLERANCE) != TestResult.TRUE) {
            derivationTypes.add(BasicDerivationType.INCLUDE_GREASE_SIG_HASH_ALGORITHMS);
        }
        return derivationTypes;
    }
    
    private static List<DerivationType> getBasicDerivationsForClient(DerivationScope derivationScope) {
        List<DerivationType> derivationTypes = new LinkedList<>();
        if(!derivationScope.isTls13Test()) {
            if(TestContext.getInstance().getSiteReport().getReceivedClientHello().containsExtension(ExtensionType.ENCRYPT_THEN_MAC)) {
                derivationTypes.add(BasicDerivationType.INCLUDE_ENCRYPT_THEN_MAC_EXTENSION);
            }
            
            if(TestContext.getInstance().getSiteReport().getReceivedClientHello().containsExtension(ExtensionType.EXTENDED_MASTER_SECRET)) {
                derivationTypes.add(BasicDerivationType.INCLUDE_EXTENDED_MASTER_SECRET_EXTENSION);
            }
        }
        return derivationTypes;
    }




}