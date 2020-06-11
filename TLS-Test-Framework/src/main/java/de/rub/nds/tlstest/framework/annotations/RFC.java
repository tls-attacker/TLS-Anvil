package de.rub.nds.tlstest.framework.annotations;

import com.fasterxml.jackson.annotation.JsonProperty;

import javax.xml.bind.annotation.XmlElement;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

@Retention(RetentionPolicy.RUNTIME)
public @interface RFC {

    @XmlElement(name = "number")
    @JsonProperty("number")
    int number();

    @XmlElement(name = "Section")
    @JsonProperty("Section")
    String section();
}
