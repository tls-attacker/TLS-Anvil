package de.rub.nds.tlstest.framework.annotations;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

enum KeyExchangeType {
    RSA,
    DH,
    ECDH,
    NONE,
    ALL
}

@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.FIELD, ElementType.METHOD})
public @interface KeyExchange {
    KeyExchangeType provided();
    KeyExchangeType[] supported() default KeyExchangeType.ALL;
}
