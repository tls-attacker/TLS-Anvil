package de.rub.nds.tlstest.framework.constants;

import de.rub.nds.tlstest.framework.annotations.categories.Compliance;
import de.rub.nds.tlstest.framework.annotations.categories.Interoperability;
import de.rub.nds.tlstest.framework.annotations.categories.Security;

import java.lang.annotation.Annotation;

public enum TestCategory {
    INTEROPERABILITY(Interoperability.class),
    COMPLIANCE(Compliance.class),
    SECURITY(Security.class);

    private final Class<? extends Annotation> annoationClass;

    TestCategory(Class<? extends Annotation> annotationClass) {
        this.annoationClass = annotationClass;
    }

    public Class<? extends Annotation> getAnnoationClass() {
        return annoationClass;
    }
}
