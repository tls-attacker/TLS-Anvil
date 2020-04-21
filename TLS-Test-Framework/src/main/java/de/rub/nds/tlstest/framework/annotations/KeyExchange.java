package de.rub.nds.tlstest.framework.annotations;

import de.rub.nds.tlstest.framework.constants.KeyExchangeType;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.FIELD, ElementType.METHOD, ElementType.TYPE})
public @interface KeyExchange {
    KeyExchangeType provided() default KeyExchangeType.NOT_SPECIFIED;
    KeyExchangeType[] supported() default {};
    boolean mergeSupportedWithClassSupported() default false;
}
