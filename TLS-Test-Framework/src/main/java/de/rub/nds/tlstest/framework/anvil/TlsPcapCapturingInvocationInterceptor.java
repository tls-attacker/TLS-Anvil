package de.rub.nds.tlstest.framework.anvil;

import de.rub.nds.anvilcore.constants.TestEndpointType;
import de.rub.nds.anvilcore.context.AnvilContext;
import de.rub.nds.anvilcore.context.AnvilTestConfig;
import de.rub.nds.anvilcore.teststate.AnvilTestRun;
import de.rub.nds.anvilcore.teststate.reporting.PcapCapturer;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.config.TlsTestConfig;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.InvocationInterceptor;
import org.junit.jupiter.api.extension.ReflectiveInvocationContext;

public class TlsPcapCapturingInvocationInterceptor implements InvocationInterceptor {

    public void interceptTestTemplateMethod(
            final Invocation<Void> invocation,
            final ReflectiveInvocationContext<Method> invocationContext,
            final ExtensionContext extensionContext)
            throws Throwable {

        AnvilTestConfig anvilConfig = AnvilContext.getInstance().getConfig();
        TlsTestConfig tlsConfig = TestContext.getInstance().getConfig();
        AnvilTestRun testRun = AnvilTestRun.forExtensionContext(extensionContext);
        TlsTestCase tlsTestCase = WorkflowRunner.getTlsTestCaseFromExtensionContext(extensionContext);
        Path path = Paths.get(anvilConfig.getOutputFolder(), "results", testRun.getTestId(), tlsTestCase.getTemporaryPcapFileName());

        // create capturer
        Files.createDirectories(path);
        PcapCapturer.Builder builder = PcapCapturer.builder().withFilePath(path.toString());

        // set filter
        if (tlsConfig.getTestEndpointMode() == TestEndpointType.SERVER) {
            builder.withBpfExpression(
                    String.format(
                            "tcp port %s", tlsConfig.getTestServerDelegate().getExtractedPort()));
        } else if (tlsConfig.getTestEndpointMode() == TestEndpointType.CLIENT) {
            builder.withBpfExpression(
                    String.format("tcp port %s", tlsConfig.getTestClientDelegate().getPort()));
        }

        // start capturing - auto closes when test is done
        try (PcapCapturer pcapCapturer = builder.build()) {
            invocation.proceed();
        }
    }
}
