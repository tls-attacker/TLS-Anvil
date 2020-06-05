package de.rub.nds.tlstest.framework.utils;

import com.fasterxml.jackson.annotation.JsonIgnoreType;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonUnwrapped;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.constants.KeyX;
import org.junit.jupiter.api.extension.ExtensionContext;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import java.lang.reflect.Method;

@XmlRootElement
@XmlAccessorType(XmlAccessType.NONE)
public class TestMethodConfig {
    private KeyX keyExchange = null;

    @JsonProperty("RFC")
    private RFC rfc = null;

    @XmlElement(name = "TlsTest")
    @JsonUnwrapped
    private TlsTest tlsTest = null;

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

    public TestMethodConfig(ExtensionContext extensionContext) {
        Method testM = extensionContext.getRequiredTestMethod();
        Class<?> testClass = extensionContext.getRequiredTestClass();

        if (testM.isAnnotationPresent(KeyExchange.class)) {
            KeyExchange annotation = KeyX.resolveKexAnnotation(extensionContext);
            this.keyExchange = new KeyX(annotation);
        }

        if (testM.isAnnotationPresent(TlsTest.class)) {
            this.tlsTest = testM.getAnnotation(TlsTest.class);;
        }

        if (testM.isAnnotationPresent(RFC.class)) {
            this.rfc = testM.getAnnotation(RFC.class);
        }
        else if (testClass.isAnnotationPresent(RFC.class)) {
            this.rfc = testClass.getAnnotation(RFC.class);
        }

        this.setMethodName(testM.getName());
        this.setClassName(testClass.getName());
        this.setDisplayName(extensionContext.getDisplayName());
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
