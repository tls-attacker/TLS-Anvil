package de.rub.nds.tlstest.framework.utils;

import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.constants.KeyX;

public class TestMethodConfig {
    private KeyX keyExchange = null;
    private TlsTest tlsTest = null;
    private RFC rfc = null;

    private String methodName = null;
    private String displayName = null;

    public TestMethodConfig() {

    }


    public KeyX getKeyExchange() {
        return keyExchange;
    }

    public void setKeyExchange(KeyX keyExchange) {
        this.keyExchange = keyExchange;
    }

    public TlsTest getTlsTest() {
        return tlsTest;
    }

    public void setTlsTest(TlsTest tlsTest) {
        this.tlsTest = tlsTest;
    }

    public RFC getRfc() {
        return rfc;
    }

    public void setRfc(RFC rfc) {
        this.rfc = rfc;
    }


    public String getMethodName() {
        return methodName;
    }

    public void setMethodName(String methodName) {
        this.methodName = methodName;
    }

    public String getDisplayName() {
        return displayName;
    }

    public void setDisplayName(String displayName) {
        this.displayName = displayName;
    }
}
