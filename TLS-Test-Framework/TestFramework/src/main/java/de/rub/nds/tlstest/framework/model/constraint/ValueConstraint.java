/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.model.constraint;

import de.rub.nds.tlstest.framework.model.DerivationType;

public class ValueConstraint {

    private final DerivationType affectedType;

    private final String evaluationMethod;
    
    private final Class<?> clazz;
    
    private final boolean dynamic;

    public ValueConstraint(DerivationType affectedType, String evaluationMethod, Class<?> clazz, boolean dynamic) {
        this.affectedType = affectedType;
        this.evaluationMethod = evaluationMethod;
        this.clazz = clazz;
        this.dynamic = dynamic;
    }

    public Class<?> getClazz() {
        return clazz;
    }

    public DerivationType getAffectedType() {
        return affectedType;
    }

    public String getEvaluationMethod() {
        return evaluationMethod;
    }

    public boolean isDynamic() {
        return dynamic;
    }

}
