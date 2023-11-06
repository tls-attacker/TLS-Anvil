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
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.InvocationInterceptor;
import org.junit.jupiter.api.extension.ReflectiveInvocationContext;

public class TlsPcapCapturingInvocationInterceptor implements InvocationInterceptor {
    private static final Logger LOGGER = LogManager.getLogger();

    public void interceptTestTemplateMethod(
            final Invocation<Void> invocation,
            final ReflectiveInvocationContext<Method> invocationContext,
            final ExtensionContext extensionContext)
            throws Throwable {

        AnvilTestConfig anvilconfig = AnvilContext.getInstance().getConfig();
        TlsTestConfig tlsConfig = TestContext.getInstance().getConfig();

        AnvilTestRun run = AnvilTestRun.forExtensionContext(extensionContext);
        Method m = extensionContext.getTestMethod().orElseThrow(() -> null);
        Path path = Paths.get(anvilconfig.getOutputFolder());
        path = path.resolve(run.getTestId());
        Files.createDirectories(path);
        TlsTestCase tlsTestCase =
                WorkflowRunner.getTlsTestCaseFromExtensionContext(extensionContext);
        path = path.resolve(tlsTestCase.getTmpPcapFileName());
        PcapCapturer.Builder builder = PcapCapturer.builder().withFilePath(path.toString());
        if (tlsConfig.getTestEndpointMode() == TestEndpointType.SERVER) {
            builder.withBpfExpression(
                    String.format(
                            "tcp port %s", tlsConfig.getTestServerDelegate().getExtractedPort()));
        } else if (tlsConfig.getTestEndpointMode() == TestEndpointType.CLIENT) {
            builder.withBpfExpression(
                    String.format("tcp port %s", tlsConfig.getTestClientDelegate().getPort()));
        }
        try (PcapCapturer pcapCapturer = builder.build()) {
            invocation.proceed();
        }
    }
}
