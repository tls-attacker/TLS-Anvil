package de.rub.nds.tlstest.framework.anvil;

import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.ParameterCombination;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.tlstest.framework.model.TlsParameterType;
import de.rwth.swc.coffee4j.model.Combination;
import java.util.LinkedList;
import java.util.List;

public class TlsParameterCombination extends ParameterCombination {

    public TlsParameterCombination(List<DerivationParameter> parameters) {
        super(parameters);
    }

    public TlsParameterCombination(
            List<DerivationParameter> parameters, DerivationScope derivationScope) {
        super(parameters, derivationScope);
    }

    public static TlsParameterCombination fromCombination(Combination combination) {
        ParameterCombination parameterCombination =
                ParameterCombination.fromCombination(combination);
        return new TlsParameterCombination(
                new LinkedList<>(parameterCombination.getParameterValues()));
    }

    public byte[] buildBitmask() {
        for (DerivationParameter listed : getParameterValues()) {
            if (listed.getParameterIdentifier().getParameterType() instanceof TlsParameterType
                    && ((TlsParameterType) listed.getParameterIdentifier().getParameterType())
                            .isBitmaskDerivation()) {
                return buildBitmask(listed.getParameterIdentifier());
            }
        }
        return null;
    }

    public byte[] buildBitmask(ParameterIdentifier parameterIdentifier) {
        DerivationParameter byteParameter =
                getParameter(parameterIdentifier); // ...BitmaskDerivation
        DerivationParameter bitParameter =
                getLinkedParameter(parameterIdentifier); // BitPositionDerivation

        byte[] constructed = new byte[(Integer) byteParameter.getSelectedValue() + 1];
        constructed[(Integer) byteParameter.getSelectedValue()] =
                (byte) (1 << (Integer) bitParameter.getSelectedValue());
        return constructed;
    }
}
