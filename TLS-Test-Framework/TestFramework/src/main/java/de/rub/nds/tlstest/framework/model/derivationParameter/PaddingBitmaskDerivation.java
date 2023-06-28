/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.model.derivationParameter;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CipherType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.model.DerivationScope;
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.model.ParameterModelFactory;
import de.rub.nds.tlstest.framework.model.constraint.ConditionalConstraint;
import de.rwth.swc.coffee4j.model.constraints.ConstraintBuilder;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Yields bitmasks to modify the padding of a plaintext. Note that the derivation may generate valid
 * paddings for mac-then-encrypt. These paddings are valid in terms of the padding scheme but are
 * invalid in regard to the position of the MAC.
 */
public class PaddingBitmaskDerivation extends DerivationParameter<Integer> {

    private static final Logger LOGGER = LogManager.getLogger();

    public PaddingBitmaskDerivation() {
        super(DerivationType.PADDING_BITMASK, Integer.class);
    }

    public PaddingBitmaskDerivation(Integer selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }

    @Override
    public List<DerivationParameter> getParameterValues(
            TestContext context, DerivationScope scope) {
        if (scope.isTls13Test()) {
            throw new RuntimeException(
                    "Padding bitmask is not configured for optional TLS 1.3 record padding");
        }

        Set<CipherSuite> cipherSuiteList = context.getFeatureExtractionResult().getCipherSuites();
        int maxCipherTextByteLen = 0;
        for (CipherSuite cipherSuite : cipherSuiteList) {
            if (AlgorithmResolver.getCipherType(cipherSuite) == CipherType.BLOCK
                    && AlgorithmResolver.getCipher(cipherSuite).getBlocksize()
                            > maxCipherTextByteLen) {
                maxCipherTextByteLen = AlgorithmResolver.getCipher(cipherSuite).getBlocksize();
            }
        }

        List<DerivationParameter> parameterValues = new LinkedList<>();
        for (int i = 0; i < maxCipherTextByteLen - 1; i++) {
            parameterValues.add(new PaddingBitmaskDerivation(i));
        }
        return parameterValues;
    }

    @Override
    public void applyToConfig(Config config, TestContext context) {}

    @Override
    public List<ConditionalConstraint> getDefaultConditionalConstraints(DerivationScope scope) {
        List<ConditionalConstraint> condConstraints = new LinkedList<>();

        condConstraints.add(getMustNotExceedPaddingLengthConstraint(scope, false));
        if (ParameterModelFactory.getDerivationsForScope(scope)
                .contains(DerivationType.INCLUDE_ENCRYPT_THEN_MAC_EXTENSION)) {
            condConstraints.add(getMustNotResultInPlausiblePadding(scope, false));
        }
        return condConstraints;
    }

    public ConditionalConstraint getMustNotExceedPaddingLengthConstraint(
            DerivationScope scope, boolean enforceEncryptThenMacMode) {
        Set<DerivationType> requiredDerivations = new HashSet<>();
        requiredDerivations.add(DerivationType.CIPHERSUITE);
        requiredDerivations.add(DerivationType.APP_MSG_LENGHT);

        if (ParameterModelFactory.getDerivationsForScope(scope)
                .contains(DerivationType.INCLUDE_ENCRYPT_THEN_MAC_EXTENSION)) {

            requiredDerivations.add(DerivationType.INCLUDE_ENCRYPT_THEN_MAC_EXTENSION);
            return new ConditionalConstraint(
                    requiredDerivations,
                    ConstraintBuilder.constrain(
                                    getType().name(),
                                    DerivationType.CIPHERSUITE.name(),
                                    DerivationType.APP_MSG_LENGHT.name(),
                                    DerivationType.INCLUDE_ENCRYPT_THEN_MAC_EXTENSION.name())
                            .by(
                                    (PaddingBitmaskDerivation paddingBitmaskDerivation,
                                            CipherSuiteDerivation cipherSuiteDerivation,
                                            AppMsgLengthDerivation appMsgLengthDerivation,
                                            IncludeEncryptThenMacExtensionDerivation
                                                    includeEncryptThenMacDerivation) -> {
                                        boolean isEncryptThenMac =
                                                includeEncryptThenMacDerivation.getSelectedValue()
                                                        || enforceEncryptThenMacMode;
                                        return chosenByteIsWithinPadding(
                                                scope,
                                                paddingBitmaskDerivation.getSelectedValue(),
                                                cipherSuiteDerivation.getSelectedValue(),
                                                appMsgLengthDerivation.getSelectedValue(),
                                                isEncryptThenMac);
                                    }));

        } else {

            return new ConditionalConstraint(
                    requiredDerivations,
                    ConstraintBuilder.constrain(
                                    getType().name(),
                                    DerivationType.CIPHERSUITE.name(),
                                    DerivationType.APP_MSG_LENGHT.name())
                            .by(
                                    (PaddingBitmaskDerivation paddingBitmaskDerivation,
                                            CipherSuiteDerivation cipherSuiteDerivation,
                                            AppMsgLengthDerivation appMsgLengthDerivation) -> {
                                        return chosenByteIsWithinPadding(
                                                scope,
                                                paddingBitmaskDerivation.getSelectedValue(),
                                                cipherSuiteDerivation.getSelectedValue(),
                                                appMsgLengthDerivation.getSelectedValue(),
                                                enforceEncryptThenMacMode);
                                    }));
        }
    }

    private int getResultingPaddingSize(
            boolean isEncryptThenMac,
            int applicationMessageContentLength,
            CipherSuite cipherSuite,
            ProtocolVersion targetVersion) {
        int blockSize = AlgorithmResolver.getCipher(cipherSuite).getBlocksize();
        int macSize = AlgorithmResolver.getMacAlgorithm(targetVersion, cipherSuite).getSize();
        if (isEncryptThenMac) {
            return blockSize - (applicationMessageContentLength % blockSize);
        } else {
            return blockSize - ((applicationMessageContentLength + macSize) % blockSize);
        }
    }

    public ConditionalConstraint getMustNotResultInPlausiblePadding(
            DerivationScope scope, boolean enforceEncryptThenMacMode) {
        Set<DerivationType> requiredDerivations = new HashSet<>();
        requiredDerivations.add(DerivationType.CIPHERSUITE);
        requiredDerivations.add(DerivationType.APP_MSG_LENGHT);
        requiredDerivations.add(DerivationType.INCLUDE_ENCRYPT_THEN_MAC_EXTENSION);

        return new ConditionalConstraint(
                requiredDerivations,
                ConstraintBuilder.constrain(
                                getType().name(),
                                DerivationType.CIPHERSUITE.name(),
                                DerivationType.APP_MSG_LENGHT.name(),
                                DerivationType.INCLUDE_ENCRYPT_THEN_MAC_EXTENSION.name(),
                                DerivationType.BIT_POSITION.name())
                        .by(
                                (PaddingBitmaskDerivation paddingBitmaskDerivation,
                                        CipherSuiteDerivation cipherSuiteDerivation,
                                        AppMsgLengthDerivation appMsgLengthDerivation,
                                        IncludeEncryptThenMacExtensionDerivation
                                                includeEncryptThenMacDerivation,
                                        BitPositionDerivation bitPositionDerivation) -> {
                                    boolean isEncryptThenMac =
                                            includeEncryptThenMacDerivation.getSelectedValue()
                                                    || enforceEncryptThenMacMode;

                                    if (isEncryptThenMac) {
                                        return resultsInPlausiblePadding(
                                                scope,
                                                paddingBitmaskDerivation,
                                                cipherSuiteDerivation,
                                                appMsgLengthDerivation,
                                                bitPositionDerivation);
                                    }
                                    // without enc-then-mac, a padding error or misread MAC is
                                    // guaranteed - we include coincidentally valid values here
                                    // as this reduces the complexity of the IPM and should not
                                    // result in false positives
                                    return true;
                                }));
    }

    private boolean resultsInPlausiblePadding(
            DerivationScope scope,
            PaddingBitmaskDerivation paddingBitmaskDerivation,
            CipherSuiteDerivation cipherSuiteDerivation,
            AppMsgLengthDerivation appMsgLengthDerivation,
            BitPositionDerivation bitPositionDerivation) {
        int selectedBitmaskBytePosition = paddingBitmaskDerivation.getSelectedValue();
        CipherSuite selectedCipherSuite = cipherSuiteDerivation.getSelectedValue();
        int selectedAppMsgLength = appMsgLengthDerivation.getSelectedValue();
        int selectedBitPosition = bitPositionDerivation.getSelectedValue();

        int resultingPaddingSize =
                getResultingPaddingSize(
                        true, selectedAppMsgLength, selectedCipherSuite, scope.getTargetVersion());
        if ((selectedBitmaskBytePosition + 1) == resultingPaddingSize
                && (1 << selectedBitPosition) == (resultingPaddingSize - 1)) {
            // padding appears to be only the lengthfield byte
            return false;
        } else if (resultingPaddingSize == 1
                && selectedBitmaskBytePosition == 0
                && (resultingPaddingSize ^ (1 << selectedBitPosition))
                        == AppMsgLengthDerivation.getAsciiLetter()
                && selectedAppMsgLength >= AppMsgLengthDerivation.getAsciiLetter()) {
            // only one byte of padding (lengthfield) gets modified in a way
            // that it matches the ASCII contents of the AppMsg data
            return false;
        }
        return true;
    }

    private boolean chosenByteIsWithinPadding(
            DerivationScope scope,
            int selectedPaddingBitmaskBytePosition,
            CipherSuite selectedCipherSuite,
            int selectedAppMsgLength,
            boolean isEncryptThenMac) {
        int resultingPaddingSize =
                getResultingPaddingSize(
                        isEncryptThenMac,
                        selectedAppMsgLength,
                        selectedCipherSuite,
                        scope.getTargetVersion());
        return resultingPaddingSize > selectedPaddingBitmaskBytePosition;
    }
}
