package de.rub.nds.tlstest.framework.annotations;


import de.rub.nds.tlstest.framework.constants.Severity;
import org.junit.jupiter.api.Test;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD, ElementType.TYPE})
@Test
public @interface TlsTest {
    String description() default "";
    Severity severity() default Severity.NOT_CLASSIFIED;
}
