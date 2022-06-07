/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.annotations.tlsVersion;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.ServerTestSiteReport;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.annotations.TlsVersion;
import de.rub.nds.tlstest.framework.junitExtensions.TlsVersionCondition;
import de.rub.nds.tlstest.framework.utils.ConditionTest;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.util.ArrayList;

@TlsVersion(supported = ProtocolVersion.TLS12)
class Tls12SuperClass {}

public class TlsVersionAnnotationSubclass extends Tls12SuperClass  {

    @RegisterExtension
    static ConditionTest ext = new ConditionTest(TlsVersionCondition.class);

    @BeforeAll
    static void setup() {
        TestContext testContext = TestContext.getInstance();
        ServerTestSiteReport report = new ServerTestSiteReport("");

        report.setVersions(new ArrayList<ProtocolVersion>() {
            {
                add(ProtocolVersion.TLS12);
                add(ProtocolVersion.SSL3);
            }
        });

        testContext.setSiteReport(report);
    }


    @TlsTest
    @TlsVersion(supported = ProtocolVersion.TLS12)
    public void execute_supported() { }

    @TlsTest
    public void execute_inheritedClassAnnotation() { }

    @TlsTest
    @TlsVersion(supported = ProtocolVersion.SSL3)
    public void execute_supported_overwrittenClassAnnotation() { }

    @TlsTest
    @TlsVersion(supported = ProtocolVersion.TLS13)
    public void not_execute_unsupported() { }

}
