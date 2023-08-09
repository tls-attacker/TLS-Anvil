package de.rub.nds.tlstest.framework.anvil;

import com.fasterxml.jackson.annotation.JsonValue;
import de.rub.nds.anvilcore.model.AnvilTestTemplate;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.model.TlsParameterType;

public abstract class TlsDerivationParameter<TypeT>
        extends DerivationParameter<TlsAnvilConfig, TypeT> {

    protected TestContext context = TestContext.getInstance();

    public TlsDerivationParameter(TlsParameterType tlsParameterType, Class<TypeT> valueClass) {
        super(valueClass, TlsAnvilConfig.class, new ParameterIdentifier(tlsParameterType));
    }

    public TlsDerivationParameter(
            TlsParameterType tlsParameterType,
            Class<TypeT> valueClass,
            ParameterIdentifier identifier) {
        super(valueClass, TlsAnvilConfig.class, identifier);
    }

    @Override
    public void applyToConfig(TlsAnvilConfig config, AnvilTestTemplate anvilTestTemplate) {}

    @Override
    protected abstract TlsDerivationParameter<TypeT> generateValue(TypeT selectedValue);

    @JsonValue
    public String jsonValue() {
        if (getSelectedValue() instanceof byte[]) {
            return ArrayConverter.bytesToHexString((byte[]) getSelectedValue());
        } else {
            return toString();
        }
    }
}
