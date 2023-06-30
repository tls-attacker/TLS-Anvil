package de.rub.nds.tlstest.framework.coffee4j.model;

import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.model.ModelType;
import de.rwth.swc.coffee4j.junit.provider.model.ModelSource;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * 
 *  This is an extended copy of the ModelFromMethod of Coffee4j.
 */
@Inherited
@Target({ElementType.ANNOTATION_TYPE, ElementType.FIELD, ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@ModelSource(ScopeBasedProvider.class)
public @interface ModelFromScope {
    String name() default "TlsTest";
    ModelType baseModel() default ModelType.GENERIC;
}
