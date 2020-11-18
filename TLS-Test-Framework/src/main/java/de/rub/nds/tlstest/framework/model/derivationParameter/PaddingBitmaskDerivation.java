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
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.model.DerivationScope;
import de.rub.nds.tlstest.framework.model.DerivationType;
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
        if(scope.isTls13Test()) {
            cipherSuiteList = context.getSiteReport().getSupportedTls13CipherSuites();
        }
        for (CipherSuite cipherSuite : cipherSuiteList) {
            if (AlgorithmResolver.getCipher(cipherSuite).getBlocksize() > maxCipherTextByteLen && AlgorithmResolver.getCipher(cipherSuite).usesPadding()) {
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
            Set<DerivationType> requiredDerivations = new HashSet<>();
            requiredDerivations.add(DerivationType.CIPHERSUITE);
            //ensure that the selected byte is within (blocksize - 1) of ciphersuite
            condConstraints.add(new ConditionalConstraint(requiredDerivations, ConstraintBuilder.constrain(getType().name(), DerivationType.CIPHERSUITE.name()).by((DerivationParameter bytePos, DerivationParameter cipherSuite) -> {
                int chosenBytePos = (Integer) bytePos.getSelectedValue();
                CipherSuiteDerivation cipherDev = (CipherSuiteDerivation) cipherSuite;
                return AlgorithmResolver.getCipher(cipherDev.getSelectedValue()).getBlocksize() - 1 > chosenBytePos;
            })));
        }

        Set<DerivationType> requiredDerivationsAppMsg = new HashSet<>();
        requiredDerivationsAppMsg.add(DerivationType.CIPHERSUITE);
        requiredDerivationsAppMsg.add(DerivationType.APP_MSG_LENGHT);

        //ensure that the selected byte is applicable for the selected 
        //app length + ciphersuite
        condConstraints.add(new ConditionalConstraint(requiredDerivationsAppMsg, ConstraintBuilder.constrain(getType().name(), DerivationType.CIPHERSUITE.name(), DerivationType.APP_MSG_LENGHT.name()).by((DerivationParameter bytePos, DerivationParameter cipherSuite, DerivationParameter appMsgLenParam) -> {
            int chosenBytePos = (Integer) bytePos.getSelectedValue();
            int appMsgLen = (Integer) appMsgLenParam.getSelectedValue();
            
            int macLen = AlgorithmResolver.getMacAlgorithm(scope.getTargetVersion(), (CipherSuite) cipherSuite.getSelectedValue()).getSize();
            int blocksize = AlgorithmResolver.getCipher((CipherSuite) cipherSuite.getSelectedValue()).getBlocksize();
            int paddingLen = blocksize - (appMsgLen + macLen % blocksize);
            return paddingLen > chosenBytePos;
        })));

        return condConstraints;
    }

}
