package de.rub.nds.tlstest.framework.annotations.tlsVersion;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.TestSiteReport;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.annotations.TlsVersion;
import de.rub.nds.tlstest.framework.junitExtensions.TlsVersionCondition;
import de.rub.nds.tlstest.framework.utils.ConditionTest;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.util.ArrayList;


public class TlsVersionAnnotationMethod {

    @RegisterExtension
    static ConditionTest ext = new ConditionTest(TlsVersionCondition.class);

    @BeforeAll
    static void setup() {
        TestContext testContext = new TestContext();
        testContext.getConfig().parse(new String[]{ "client", "-port", "443" });
        TestSiteReport report = new TestSiteReport("");

        report.setVersions(new ArrayList<ProtocolVersion>() {
            {
                add(ProtocolVersion.TLS12);
                add(ProtocolVersion.SSL3);
            }
        });

        testContext.getConfig().setSiteReport(report);
    }


    @TlsTest
    @TlsVersion(supported = ProtocolVersion.TLS12)
    public void execute_supported() { }

    @TlsTest
    @TlsVersion(supported = ProtocolVersion.SSL3)
    public void execute_supported_overwrittenClassAnnotation() { }

    @TlsTest
    @TlsVersion(supported = ProtocolVersion.TLS13)
    public void not_execute_unsupported() { }

    @TlsTest
    public void not_execute_annotationIsMissing() { }

}
