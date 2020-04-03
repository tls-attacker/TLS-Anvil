package de.rub.nds.tlstest.framework.annotations;


import de.rub.nds.tlstest.framework.junitExtensions.TestContextParameterResolver;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD, ElementType.TYPE})
@Test
@ExtendWith(TestContextParameterResolver.class)
public @interface TlsTest {

}
