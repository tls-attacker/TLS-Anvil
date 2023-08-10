package de.rub.nds.tlstest.framework.anvil;

import com.fasterxml.jackson.annotation.JsonValue;
import de.rub.nds.anvilcore.model.AnvilTestTemplate;
import de.rub.nds.anvilcore.model.ParameterCombination;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.tlstest.framework.model.TlsParameterType;
import de.rwth.swc.coffee4j.model.Combination;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

public class TlsParameterCombination extends ParameterCombination {

    public TlsParameterCombination(List<DerivationParameter> parameters) {
        super(parameters);
    }

    public TlsParameterCombination(
            List<DerivationParameter> parameters, AnvilTestTemplate anvilTestTemplate) {
        super(parameters, anvilTestTemplate);
    }

    public static TlsParameterCombination fromCombination(Combination combination) {
        ParameterCombination parameterCombination =
                ParameterCombination.fromCombination(combination);
        return new TlsParameterCombination(
                new LinkedList<>(parameterCombination.getParameterValues()));
    }

    public static TlsParameterCombination fromArgumentsAccessor(
            ArgumentsAccessor argumentsAccessor, AnvilTestTemplate anvilTestTemplate) {
        ParameterCombination parameterCombination =
                ParameterCombination.fromArgumentsAccessor(argumentsAccessor, anvilTestTemplate);
        TlsParameterCombination tlsParameterCombination =
                new TlsParameterCombination(parameterCombination.getParameterValues());
        // set separately so we do not fetch static parameters twice
        tlsParameterCombination.setDerivationScope(anvilTestTemplate);
        return tlsParameterCombination;
    }

    public byte[] buildBitmask() {
        for (DerivationParameter listed : getParameterValues()) {
            if (((TlsParameterType) listed.getParameterIdentifier().getParameterType())
                    .isBitmaskDerivation()) {
                return buildBitmask(listed.getParameterIdentifier());
            }
        }
        return null;
    }

    public byte[] buildBitmask(ParameterIdentifier parameterIdentifier) {
        DerivationParameter byteParameter = getParameter(parameterIdentifier);      // ...BitmaskDerivation
        DerivationParameter bitParameter = getLinkedParameter(parameterIdentifier); // BitPositionDerivation

        byte[] constructed = new byte[(Integer) byteParameter.getSelectedValue() + 1];
        constructed[(Integer) byteParameter.getSelectedValue()] =
                (byte) (1 << (Integer) bitParameter.getSelectedValue());
        return constructed;
    }
}
