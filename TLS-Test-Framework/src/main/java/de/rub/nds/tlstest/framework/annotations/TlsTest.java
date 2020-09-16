/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.annotations;


import com.fasterxml.jackson.annotation.JsonProperty;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import org.junit.jupiter.api.Test;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD, ElementType.TYPE})
@Test
@XmlAccessorType(XmlAccessType.NONE)
public @interface TlsTest {
    @XmlElement(name = "Description")
    @JsonProperty("Description")
    String description() default "";

    @XmlElement(name = "SecuritySeverity")
    @JsonProperty("SecuritySeverity")
    SeverityLevel securitySeverity() default SeverityLevel.INFORMATIONAL;

    @XmlElement(name = "InteroperabilitySeverity")
    @JsonProperty("InteroperabilitySeverity")
    SeverityLevel interoperabilitySeverity() default SeverityLevel.INFORMATIONAL;
}
