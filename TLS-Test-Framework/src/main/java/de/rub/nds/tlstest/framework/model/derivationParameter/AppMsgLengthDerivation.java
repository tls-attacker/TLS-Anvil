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
public class AppMsgLengthDerivation extends DerivationParameter<Integer> {

    public AppMsgLengthDerivation() {
        super(DerivationType.APP_MSG_LENGHT, Integer.class);
    }

    public AppMsgLengthDerivation(Integer selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }

    @Override
    public List<DerivationParameter> getParameterValues(TestContext context, DerivationScope scope) {
        int maxCipherTextByteLen = 0;
        for (CipherSuite cipherSuite : context.getSiteReport().getCipherSuites()) {
            if (AlgorithmResolver.getCipher(cipherSuite).getBlocksize() > maxCipherTextByteLen) {
                maxCipherTextByteLen = AlgorithmResolver.getCipher(cipherSuite).getBlocksize();
            }
        }

        List<DerivationParameter> parameterValues = new LinkedList<>();
        for (int i = 1; i <= maxCipherTextByteLen; i++) {
            parameterValues.add(new AppMsgLengthDerivation(i));
        }
        return parameterValues;
    }

    @Override
    public void applyToConfig(Config config, TestContext context) {
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < getSelectedValue(); i++) {
            builder.append("A");
        }
        config.setDefaultApplicationMessageData(builder.toString());
    }

    @Override
    public List<ConditionalConstraint> getConditionalConstraints(DerivationScope scope) {
        ConstraintHelper constraintHelper = new ConstraintHelper();
        List<ConditionalConstraint> condConstraints = new LinkedList<>();
        
        if (constraintHelper.multipleBlocksizesModeled(scope)) {
            Set<DerivationType> requiredDerivations = new HashSet<>();
            requiredDerivations.add(DerivationType.CIPHERSUITE);
            

            //msg length must not exceed blocklength
            condConstraints.add(new ConditionalConstraint(requiredDerivations, ConstraintBuilder.constrain(DerivationType.APP_MSG_LENGHT.name(), DerivationType.CIPHERSUITE.name()).by((DerivationParameter msgLenParam, DerivationParameter cipherSuite) -> {
                int msgLen = (Integer) msgLenParam.getSelectedValue();
                CipherSuiteDerivation cipherDev = (CipherSuiteDerivation) cipherSuite;
                return AlgorithmResolver.getCipher(cipherDev.getSelectedValue()).getBlocksize() >= msgLen;
            })));
        }
        return condConstraints;
    }

}
