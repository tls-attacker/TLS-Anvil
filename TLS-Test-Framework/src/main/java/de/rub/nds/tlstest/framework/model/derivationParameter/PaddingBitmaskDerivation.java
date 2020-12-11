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
import de.rub.nds.tlstest.framework.model.constraint.ConstraintHelper;
import de.rwth.swc.coffee4j.model.constraints.ConstraintBuilder;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

/**
 *
 * @author marcel
 */
public class PaddingBitmaskDerivation extends DerivationParameter<Integer> {

    public PaddingBitmaskDerivation() {
        super(DerivationType.PADDING_BITMASK, Integer.class);
    }

    public PaddingBitmaskDerivation(Integer selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }

    @Override
    public List<DerivationParameter> getParameterValues(TestContext context, DerivationScope scope) {
        int maxCipherTextByteLen = 0;
        Set<CipherSuite> cipherSuiteList = context.getSiteReport().getCipherSuites();
        if (scope.isTls13Test()) {
            cipherSuiteList = context.getSiteReport().getSupportedTls13CipherSuites();
        }
        for (CipherSuite cipherSuite : cipherSuiteList) {
            if (AlgorithmResolver.getCipher(cipherSuite).getBlocksize() > maxCipherTextByteLen && cipherSuite.isUsingPadding(scope.getTargetVersion()) && AlgorithmResolver.getCipherType(cipherSuite) != CipherType.AEAD) {
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
    public void applyToConfig(Config config, TestContext context) {
    }

    @Override
    public List<ConditionalConstraint> getConditionalConstraints(DerivationScope scope) {
        List<ConditionalConstraint> condConstraints = new LinkedList<>();

        if (ConstraintHelper.multipleBlocksizesModeled(scope)) {
            condConstraints.add(getMustBeWithinBlocksizeConstraint());
        }

        condConstraints.add(getMustNotExceedPaddingLengthConstraint(scope));
        condConstraints.add(getMustNotResultInZeroPaddingLength(scope));
        return condConstraints;
    }

    private ConditionalConstraint getMustBeWithinBlocksizeConstraint() {
        Set<DerivationType> requiredDerivations = new HashSet<>();
        requiredDerivations.add(DerivationType.CIPHERSUITE);

        return new ConditionalConstraint(requiredDerivations, ConstraintBuilder.constrain(getType().name(), DerivationType.CIPHERSUITE.name()).by((DerivationParameter bytePos, DerivationParameter cipherSuite) -> {
            int chosenBytePos = (Integer) bytePos.getSelectedValue();
            CipherSuiteDerivation cipherDev = (CipherSuiteDerivation) cipherSuite;
            return AlgorithmResolver.getCipher(cipherDev.getSelectedValue()).getBlocksize() - 1 > chosenBytePos;
        }));
    }

    private ConditionalConstraint getMustNotExceedPaddingLengthConstraint(DerivationScope scope) {
        Set<DerivationType> requiredDerivations = new HashSet<>();
        requiredDerivations.add(DerivationType.CIPHERSUITE);
        requiredDerivations.add(DerivationType.APP_MSG_LENGHT);

        if (ParameterModelFactory.getDerivationsForScope(scope).contains(DerivationType.INCLUDE_ENCRYPT_THEN_MAC_EXTENSION)) {

            requiredDerivations.add(DerivationType.INCLUDE_ENCRYPT_THEN_MAC_EXTENSION);
            return new ConditionalConstraint(requiredDerivations, ConstraintBuilder.constrain(getType().name(), DerivationType.CIPHERSUITE.name(), DerivationType.APP_MSG_LENGHT.name(), DerivationType.INCLUDE_ENCRYPT_THEN_MAC_EXTENSION.name()).by((DerivationParameter chosenPaddingModificationBytePositionParam, DerivationParameter cipherSuiteParam, DerivationParameter applicationMessageLengthParam, DerivationParameter encryptThenMacParam) -> {
                boolean isEncryptThenMac = (Boolean) encryptThenMacParam.getSelectedValue();
                int chosenPaddingModificationBytePosition = (Integer) chosenPaddingModificationBytePositionParam.getSelectedValue();
                int resultingPaddingSize = getResultingPaddingSize(isEncryptThenMac, (Integer) applicationMessageLengthParam.getSelectedValue(), (CipherSuite) cipherSuiteParam.getSelectedValue(), scope.getTargetVersion());
                return resultingPaddingSize > chosenPaddingModificationBytePosition;
            }));

        } else {

            return new ConditionalConstraint(requiredDerivations, ConstraintBuilder.constrain(getType().name(), DerivationType.CIPHERSUITE.name(), DerivationType.APP_MSG_LENGHT.name()).by((DerivationParameter chosenPaddingModificationBytePositionParam, DerivationParameter cipherSuiteParam, DerivationParameter applicationMessageLengthParam) -> {
                int chosenPaddingModificationBytePosition = (Integer) chosenPaddingModificationBytePositionParam.getSelectedValue();
                int resultingPaddingSize = getResultingPaddingSize(false, (Integer) applicationMessageLengthParam.getSelectedValue(), (CipherSuite) cipherSuiteParam.getSelectedValue(), scope.getTargetVersion());
                return resultingPaddingSize > chosenPaddingModificationBytePosition;
            }));

        }
    }

    private int getResultingPaddingSize(boolean isEncryptThenMac, int applicationMessageContentLength, CipherSuite cipherSuite, ProtocolVersion targetVersion) {
        int blockSize = AlgorithmResolver.getCipher(cipherSuite).getBlocksize();
        int macSize = AlgorithmResolver.getMacAlgorithm(targetVersion, cipherSuite).getSize();
        if (isEncryptThenMac) {
            return blockSize - (applicationMessageContentLength % blockSize);
        } else {
            return blockSize - (applicationMessageContentLength + macSize % blockSize);
        }
    }

    private ConditionalConstraint getMustNotResultInZeroPaddingLength(DerivationScope scope) {
        //the ciphertext contains a padding length byte which must not be zero
        //as implementations can't determine that this case is invalid
        Set<DerivationType> requiredDerivations = new HashSet<>();
        requiredDerivations.add(DerivationType.CIPHERSUITE);
        requiredDerivations.add(DerivationType.APP_MSG_LENGHT);

        if (ParameterModelFactory.getDerivationsForScope(scope).contains(DerivationType.INCLUDE_ENCRYPT_THEN_MAC_EXTENSION)) {

            requiredDerivations.add(DerivationType.INCLUDE_ENCRYPT_THEN_MAC_EXTENSION);
            return new ConditionalConstraint(requiredDerivations, ConstraintBuilder.constrain(getType().name(), DerivationType.CIPHERSUITE.name(), DerivationType.APP_MSG_LENGHT.name(), DerivationType.INCLUDE_ENCRYPT_THEN_MAC_EXTENSION.name(), DerivationType.BIT_POSITION.name()).by((DerivationParameter chosenPaddingModificationBytePositionParam, DerivationParameter cipherSuiteParam, DerivationParameter applicationMessageLengthParam, DerivationParameter encryptThenMacParam, DerivationParameter bitPosition) -> {
                boolean isEncryptThenMac = (Boolean) encryptThenMacParam.getSelectedValue();
                int chosenPaddingModificationBytePosition = (Integer) chosenPaddingModificationBytePositionParam.getSelectedValue();
                int resultingPaddingSize = getResultingPaddingSize(isEncryptThenMac, (Integer) applicationMessageLengthParam.getSelectedValue(), (CipherSuite) cipherSuiteParam.getSelectedValue(), scope.getTargetVersion());
                int bitShifts = (Integer) bitPosition.getSelectedValue();
                if ((chosenPaddingModificationBytePosition + 1) == resultingPaddingSize && (1 << bitShifts) == (resultingPaddingSize - 1)) {
                    return false;
                }
                return true;
            }));

        } else {

            return new ConditionalConstraint(requiredDerivations, ConstraintBuilder.constrain(getType().name(), DerivationType.CIPHERSUITE.name(), DerivationType.APP_MSG_LENGHT.name(), DerivationType.BIT_POSITION.name()).by((DerivationParameter chosenPaddingModificationBytePositionParam, DerivationParameter cipherSuiteParam, DerivationParameter applicationMessageLengthParam, DerivationParameter bitPosition) -> {
                int chosenPaddingModificationBytePosition = (Integer) chosenPaddingModificationBytePositionParam.getSelectedValue();
                int resultingPaddingSize = getResultingPaddingSize(false, (Integer) applicationMessageLengthParam.getSelectedValue(), (CipherSuite) cipherSuiteParam.getSelectedValue(), scope.getTargetVersion());
                int bitShifts = (Integer) bitPosition.getSelectedValue();
                if ((chosenPaddingModificationBytePosition + 1) == resultingPaddingSize && (1 << bitShifts) == (resultingPaddingSize - 1)) {
                    return false;
                }
                return true;
            }));

        }
    }

}
