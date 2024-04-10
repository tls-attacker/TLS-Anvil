package de.rub.nds.tlstest.framework.anvil;

import de.rub.nds.anvilcore.model.parameter.ParameterScope;
import de.rub.nds.tlstest.framework.model.TlsParameterType;

public class BitPositionParameterScope extends ParameterScope {

    TlsParameterType linkedType;

    public BitPositionParameterScope(TlsParameterType linkedType) {
        this.linkedType = linkedType;
    }

    @Override
    public String getUniqueScopeIdentifier() {
        return linkedType.name();
    }
}
