package de.rub.nds.tlstest.framework.utils;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonUnwrapped;
import de.rub.nds.tlstest.framework.annotations.*;
import de.rub.nds.tlstest.framework.constants.KeyX;
import org.junit.jupiter.api.extension.ExtensionContext;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import java.lang.annotation.Annotation;
import java.lang.reflect.Method;

@XmlRootElement
@XmlAccessorType(XmlAccessType.NONE)
public class TestMethodConfig {
    private KeyX keyExchange = null;
    private Method testMethod = null;
    private Class<?> testClass = null;

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

    @XmlElement(name = "TlsVersion")
    @JsonUnwrapped
    private TlsVersion tlsVersion = null;

    public TestMethodConfig() {

    }

    public TestMethodConfig(ExtensionContext extensionContext) {
        testMethod = extensionContext.getRequiredTestMethod();
        testClass = extensionContext.getRequiredTestClass();

        if (testMethod.isAnnotationPresent(KeyExchange.class) || testClass.isAnnotationPresent(KeyExchange.class)) {
            KeyExchange annotation = KeyX.resolveKexAnnotation(extensionContext);
            this.keyExchange = new KeyX(annotation);
        }

        if (testMethod.isAnnotationPresent(TlsTest.class)) {
            this.tlsTest = testMethod.getAnnotation(TlsTest.class);;
        }

        this.rfc = this.resolveAnnotation(RFC.class);
        this.tlsVersion = this.resolveAnnotation(TlsVersion.class);

        this.setMethodName(testMethod.getName());
        this.setClassName(testClass.getName());
        this.setDisplayName(extensionContext.getDisplayName());
    }

    private <T extends Annotation> T resolveAnnotation(Class<T> clazz) {
        if (testMethod.isAnnotationPresent(clazz)) {
            return testMethod.getAnnotation(clazz);
        }
        else if (testClass.isAnnotationPresent(clazz)) {
            return testClass.getAnnotation(clazz);
        }

        return null;
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

    public TlsVersion getTlsVersion() {
        return tlsVersion;
    }

    public void setTlsVersion(TlsVersion tlsVersion) {
        this.tlsVersion = tlsVersion;
    }
}
