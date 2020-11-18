package de.rub.nds.tlstest.framework.model.derivationParameter;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.model.DerivationScope;
import de.rub.nds.tlstest.framework.model.DerivationType;
import java.util.LinkedList;
import java.util.List;

/**
 *
 */
public class SigAndHashDerivation extends DerivationParameter<SignatureAndHashAlgorithm> {

    public SigAndHashDerivation() {
        super(DerivationType.SIG_HASH_ALGORIHTM, SignatureAndHashAlgorithm.class);
    }
    
    public SigAndHashDerivation(SignatureAndHashAlgorithm selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }
    
    @Override
    public List<DerivationParameter> getParameterValues(TestContext context, DerivationScope scope) {
        List<DerivationParameter> parameterValues = new LinkedList<>();
        for(SignatureAndHashAlgorithm sigHashAlog : context.getSiteReport().getSupportedSignatureAndHashAlgorithms()) {
            parameterValues.add(new SigAndHashDerivation(sigHashAlog));
        }
        return parameterValues;
    }

    @Override
    public void applyToConfig(Config config, TestContext context) {
    }

}
