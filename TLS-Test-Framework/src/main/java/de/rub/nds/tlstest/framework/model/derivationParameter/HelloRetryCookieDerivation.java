/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.model.derivationParameter;

import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.tlstest.framework.anvil.TlsAnvilConfig;
import de.rub.nds.tlstest.framework.anvil.TlsDerivationParameter;
import de.rub.nds.tlstest.framework.model.TlsParameterType;
import java.util.LinkedList;
import java.util.List;

public class HelloRetryCookieDerivation extends TlsDerivationParameter<byte[]> {

    public HelloRetryCookieDerivation() {
        super(TlsParameterType.HELLO_RETRY_COOKIE, byte[].class);
    }

    public HelloRetryCookieDerivation(byte[] selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }

    @Override
    public void applyToConfig(TlsAnvilConfig config, DerivationScope derivationScope) {
        config.getTlsConfig().setDefaultExtensionCookie(getSelectedValue());
    }

    @Override
    protected TlsDerivationParameter<byte[]> generateValue(byte[] selectedValue) {
        return new HelloRetryCookieDerivation(selectedValue);
    }

    @Override
    public List<DerivationParameter<TlsAnvilConfig, byte[]>> getParameterValues(
            DerivationScope derivationScope) {
        List<DerivationParameter<TlsAnvilConfig, byte[]>> derivationParameters = new LinkedList<>();
        derivationParameters.add(new HelloRetryCookieDerivation(new byte[] {0x55}));
        derivationParameters.add(
                new HelloRetryCookieDerivation(
                        new byte[] {
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
                        }));
        derivationParameters.add(
                new HelloRetryCookieDerivation(
                        new byte[] {
                            (byte) 0xFF,
                            (byte) 0xFF,
                            (byte) 0xFF,
                            (byte) 0xFF,
                            (byte) 0xFF,
                            (byte) 0xFF,
                            (byte) 0xFF,
                            (byte) 0xFF
                        }));
        derivationParameters.add(
                new HelloRetryCookieDerivation(
                        new byte[] {
                            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                            0x01, 0x01, 0x01, 0x01,
                        }));
        return derivationParameters;
    }
}
