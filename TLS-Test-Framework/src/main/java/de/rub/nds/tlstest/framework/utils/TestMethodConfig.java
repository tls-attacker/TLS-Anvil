package de.rub.nds.tlstest.framework.utils;

import com.fasterxml.jackson.annotation.JsonIgnoreType;
import com.fasterxml.jackson.annotation.JsonProperty;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.constants.KeyX;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.NONE)
public class TestMethodConfig {
    private KeyX keyExchange = null;
    private TlsTest tlsTest = null;
    private RFC rfc = null;

    @XmlElement(name = "MethodName")
    @JsonProperty("MethodName")
    private String methodName = null;

    @XmlElement(name = "DisplayName")
    @JsonProperty("DisplayName")
    private String displayName = null;

    @XmlElement(name = "ClassName")
    @JsonProperty("ClassName")
    private String className = null;

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

    public String getClassName() {
        return className;
    }

    public void setClassName(String className) {
        this.className = className;
    }
}
