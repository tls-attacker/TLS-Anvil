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
import de.rub.nds.tlstest.framework.coffee4j.TlsTestsuiteReporter;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rwth.swc.coffee4j.engine.characterization.delta.ImprovedDeltaDebugging;
import de.rwth.swc.coffee4j.junit.CombinatorialTest;
import de.rwth.swc.coffee4j.junit.provider.configuration.characterization.EnableFaultCharacterization;
import de.rwth.swc.coffee4j.junit.provider.configuration.reporter.Reporter;
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
@CombinatorialTest
@EnableFaultCharacterization(ImprovedDeltaDebugging.class)
@Reporter(TlsTestsuiteReporter.class)
@XmlAccessorType(XmlAccessType.NONE)
public @interface TlsTest {
    @XmlElement(name = "Description")
    @JsonProperty("Description")
    String description() default "";

    SeverityLevel securitySeverity() default SeverityLevel.INFORMATIONAL;
    SeverityLevel interoperabilitySeverity() default SeverityLevel.INFORMATIONAL;
}
