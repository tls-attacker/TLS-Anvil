package de.rub.nds.tlstest.framework.anvil;

import com.fasterxml.jackson.annotation.JsonValue;
import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.ParameterCombination;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.tlstest.framework.model.TlsParameterType;
import de.rwth.swc.coffee4j.model.Combination;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

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
        return new TlsParameterCombination(parameterCombination.getParameterValues());
    }

    public static TlsParameterCombination fromArgumentsAccessor(
            ArgumentsAccessor argumentsAccessor, DerivationScope derivationScope) {
        ParameterCombination parameterCombination =
                ParameterCombination.fromArgumentsAccessor(argumentsAccessor, derivationScope);
        return new TlsParameterCombination(
                parameterCombination.getParameterValues(),
                parameterCombination.getDerivationScope());
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
        DerivationParameter byteParameter = getParameter(parameterIdentifier);
        DerivationParameter bitParameter = getLinkedParameter(parameterIdentifier);

        byte[] constructed = new byte[(Integer) byteParameter.getSelectedValue() + 1];
        constructed[(Integer) byteParameter.getSelectedValue()] =
                (byte) (1 << (Integer) bitParameter.getSelectedValue());
        return constructed;
    }

    @JsonValue
    private Map<String, DerivationParameter> jsonObject() {
        Map<String, DerivationParameter> res = new HashMap<>();
        for (DerivationParameter i : getParameterValues()) {
            res.put(i.getParameterIdentifier().name(), i);
        }
        return res;
    }
}
