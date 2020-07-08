package de.rub.nds.tlstest.framework.annotations;

import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;

import java.lang.annotation.*;

@Inherited
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.FIELD, ElementType.METHOD, ElementType.TYPE})
public @interface KeyExchange {
    KeyExchangeType[] supported() default {};
    boolean mergeSupportedWithClassSupported() default false;
    boolean requiresServerKeyExchMsg() default false;
}
