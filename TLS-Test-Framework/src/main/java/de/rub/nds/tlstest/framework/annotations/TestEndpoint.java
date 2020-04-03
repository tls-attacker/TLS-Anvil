package de.rub.nds.tlstest.framework.annotations;

import de.rub.nds.tlstest.framework.constants.TestEndpointType;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;


@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface TestEndpoint {
    TestEndpointType endpoint() default TestEndpointType.BOTH;
}
