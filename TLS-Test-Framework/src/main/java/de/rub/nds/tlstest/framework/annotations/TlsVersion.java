package de.rub.nds.tlstest.framework.annotations;

import com.fasterxml.jackson.annotation.JsonProperty;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;

import java.lang.annotation.*;

@Inherited
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD, ElementType.TYPE})
public @interface TlsVersion {

    @JsonProperty("TlsVersion")
    ProtocolVersion supported();
}
