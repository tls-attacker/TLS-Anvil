/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2022 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.constants;

import de.rub.nds.tlstest.framework.annotations.categories.AlertCategory;
import de.rub.nds.tlstest.framework.annotations.categories.CVECategory;
import de.rub.nds.tlstest.framework.annotations.categories.CertificateCategory;
import de.rub.nds.tlstest.framework.annotations.categories.ComplianceCategory;
import de.rub.nds.tlstest.framework.annotations.categories.CryptoCategory;
import de.rub.nds.tlstest.framework.annotations.categories.DeprecatedFeatureCategory;
import de.rub.nds.tlstest.framework.annotations.categories.HandshakeCategory;
import de.rub.nds.tlstest.framework.annotations.categories.InteroperabilityCategory;
import de.rub.nds.tlstest.framework.annotations.categories.MessageStructureCategory;
import de.rub.nds.tlstest.framework.annotations.categories.RecordLayerCategory;
import de.rub.nds.tlstest.framework.annotations.categories.SecurityCategory;

import java.lang.annotation.Annotation;

public enum TestCategory {
    ALERT(AlertCategory.class),
    CVE(CVECategory.class),
    CERTIFICATE(CertificateCategory.class),
    CRYPTO(CryptoCategory.class),
    DEPRECATED(DeprecatedFeatureCategory.class),
    HANDSHAKE(HandshakeCategory.class),
    MESSAGESTRUCTURE(MessageStructureCategory.class),
    RECORDLAYER(RecordLayerCategory.class),
    INTEROPERABILITY(InteroperabilityCategory.class),
    COMPLIANCE(ComplianceCategory.class),
    SECURITY(SecurityCategory.class);

    private final Class<? extends Annotation> annoationClass;

    TestCategory(Class<? extends Annotation> annotationClass) {
        this.annoationClass = annotationClass;
    }

    public Class<? extends Annotation> getAnnoationClass() {
        return annoationClass;
    }
}
