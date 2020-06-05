package de.rub.nds.tlstest.framework.annotations;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

@Retention(RetentionPolicy.RUNTIME)
public @interface RFC {

    @JsonProperty("number")
    int number();

    @JsonProperty("Section")
    String section();
}
