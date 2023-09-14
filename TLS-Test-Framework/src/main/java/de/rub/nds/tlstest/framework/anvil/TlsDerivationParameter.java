package de.rub.nds.tlstest.framework.anvil;

import com.fasterxml.jackson.annotation.JsonValue;
import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.model.TlsParameterType;

public abstract class TlsDerivationParameter<TypeT> extends DerivationParameter<Config, TypeT> {

    protected TestContext context = TestContext.getInstance();

    public TlsDerivationParameter(TlsParameterType tlsParameterType, Class<TypeT> valueClass) {
        super(valueClass, Config.class, new ParameterIdentifier(tlsParameterType));
    }

    public TlsDerivationParameter(
            TlsParameterType tlsParameterType,
            Class<TypeT> valueClass,
            ParameterIdentifier identifier) {
        super(valueClass, Config.class, identifier);
    }

    @Override
    public void applyToConfig(Config config, DerivationScope derivationScope) {}

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
