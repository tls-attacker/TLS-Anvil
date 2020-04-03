package de.rub.nds.tlstest.framework.annotations;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

@Retention(RetentionPolicy.RUNTIME)
public @interface RFC {
    int number();
    String section();
}
