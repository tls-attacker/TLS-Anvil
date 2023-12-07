package de.rub.nds.tlstest.framework.anvil;

import de.rub.nds.anvilcore.constants.TestEndpointType;
import de.rub.nds.anvilcore.context.AnvilContext;
import de.rub.nds.anvilcore.context.AnvilTestConfig;
import de.rub.nds.anvilcore.teststate.AnvilTestRun;
import de.rub.nds.anvilcore.teststate.reporting.PcapCapturer;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.config.TlsTestConfig;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import java.io.IOException;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.InvocationInterceptor;
import org.junit.jupiter.api.extension.ReflectiveInvocationContext;
import org.pcap4j.core.PcapNativeException;

public class TlsPcapCapturingInvocationInterceptor implements InvocationInterceptor {

    private static final Logger LOGGER = LogManager.getLogger();

    public void interceptTestTemplateMethod(
            final Invocation<Void> invocation,
            final ReflectiveInvocationContext<Method> invocationContext,
            final ExtensionContext extensionContext)
            throws Throwable {

        if (AnvilContext.getInstance().getConfig().isDisableTcpDump()) {
            invocation.proceed();
            return;
        }

        AnvilTestConfig anvilConfig = AnvilContext.getInstance().getConfig();
        TlsTestConfig tlsConfig = TestContext.getInstance().getConfig();
        AnvilTestRun testRun = AnvilTestRun.forExtensionContext(extensionContext);
        TlsTestCase tlsTestCase =
                WorkflowRunner.getTlsTestCaseFromExtensionContext(extensionContext);
        Path folderPath = Paths.get(anvilConfig.getOutputFolder(), "results", testRun.getTestId());

        PcapCapturer.Builder builder = createCapturer(folderPath, tlsTestCase);
        builder.withTestCase(tlsTestCase);

        setFilter(tlsConfig, builder);

        // start capturing - auto closes when test is done
        try (PcapCapturer pcapCapturer = builder.build()) {
            invocation.proceed();
        } catch (PcapNativeException ex) {
            LOGGER.error("Failed to start packet capture: {}", ex.getLocalizedMessage());
            // continue invocation even if pcap can not be recorded
            invocation.proceed();
        }
    }

    private PcapCapturer.Builder createCapturer(Path folderPath, TlsTestCase tlsTestCase)
            throws IOException {
        Files.createDirectories(folderPath);
        Path filePath = folderPath.resolve(tlsTestCase.getTemporaryPcapFileName());
        PcapCapturer.Builder builder = PcapCapturer.builder().withFilePath(filePath.toString());
        return builder;
    }

    private void setFilter(TlsTestConfig tlsConfig, PcapCapturer.Builder builder) {
        String transportProtocolPrefix = resolveTransportProtocolPrefix(tlsConfig);
        if (tlsConfig.getTestEndpointMode() == TestEndpointType.SERVER) {
            builder.withBpfExpression(
                    String.format(
                            transportProtocolPrefix + " port %s",
                            tlsConfig.getTestServerDelegate().getExtractedPort()));
        } else if (tlsConfig.getTestEndpointMode() == TestEndpointType.CLIENT) {
            builder.withBpfExpression(
                    String.format(
                            transportProtocolPrefix + " port %s",
                            tlsConfig.getTestClientDelegate().getPort()));
        }
    }

    public static String resolveTransportProtocolPrefix(TlsTestConfig tlsConfig) {
        String transportProtocolPrefix = "tcp";
        if (tlsConfig.isUseDTLS()) {
            transportProtocolPrefix = "udp";
        }
        return transportProtocolPrefix;
    }
}
