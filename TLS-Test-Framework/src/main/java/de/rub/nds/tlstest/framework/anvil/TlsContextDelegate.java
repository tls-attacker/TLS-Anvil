package de.rub.nds.tlstest.framework.anvil;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import de.rub.nds.anvilcore.context.ApplicationSpecificContextDelegate;
import de.rub.nds.anvilcore.teststate.AnvilTestState;
import de.rub.nds.anvilcore.teststate.AnvilTestStateContainer;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceSerializer;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.execution.TlsTestState;
import de.rub.nds.tlstest.framework.utils.ExecptionPrinter;
import de.rub.nds.tlstest.framework.utils.Utils;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class TlsContextDelegate implements ApplicationSpecificContextDelegate {
    private static final Logger LOGGER = LogManager.getLogger();

    @Override
    public void onTestFinished(String uniqueId, AnvilTestStateContainer finishedContainer) {
        serialize(finishedContainer);
    }

    private String getSerializationPath(AnvilTestStateContainer stateContainer) {
        String method = stateContainer.getTestMethod().getName();
        // truncate the class name to shorten the path length
        // basically throw away the common package, i.e. everything before "server" or "client"
        String pName = "de.rub.nds.tlstest.suite.tests.";
        method = method.replace(pName, "");

        String[] folderComponents = method.split("\\.");

        return Paths.get(TestContext.getInstance().getConfig().getOutputFolder(), folderComponents)
                .toString();
    }

    private void serialize(AnvilTestStateContainer stateContainer) {
        ObjectMapper mapper = new ObjectMapper();
        mapper.setVisibility(
                mapper.getSerializationConfig()
                        .getDefaultVisibilityChecker()
                        .withFieldVisibility(JsonAutoDetect.Visibility.NONE)
                        .withGetterVisibility(JsonAutoDetect.Visibility.NONE)
                        .withSetterVisibility(JsonAutoDetect.Visibility.NONE)
                        .withCreatorVisibility(JsonAutoDetect.Visibility.NONE));

        if (TestContext.getInstance().getConfig().isPrettyPrintJSON()) {
            mapper.enable(SerializationFeature.INDENT_OUTPUT);
        }

        String targetFolder = getSerializationPath(stateContainer);

        String containerResultPath = Paths.get(targetFolder, "_containerResult.json").toString();
        File f = new File(containerResultPath);
        StringBuilder errorMsg = new StringBuilder();
        Utils.createEmptyFile(containerResultPath);

        try {
            mapper.writeValue(f, stateContainer);
        } catch (Exception e) {
            LOGGER.error(
                    "Failed to serialize AnnotatedStateContainer ({})",
                    stateContainer.getTestMethod().getName(),
                    e);
            errorMsg.append("Failed to serialize AnnotatedStateContainer\n");
            errorMsg.append(ExecptionPrinter.stacktraceToString(e));
        }

        if (TestContext.getInstance().getConfig().isExportTraces()) {
            try {
                FileOutputStream fos =
                        new FileOutputStream(Paths.get(targetFolder, "traces.zip").toString());
                ZipOutputStream zipOut = new ZipOutputStream(fos);
                for (AnvilTestState anvilState : stateContainer.getStates()) {
                    TlsTestState tlsTestState = (TlsTestState) anvilState;
                    ZipEntry zipEntry = new ZipEntry(tlsTestState.getUuid() + ".xml");
                    zipOut.putNextEntry(zipEntry);
                    try {
                        String serialized =
                                WorkflowTraceSerializer.write(tlsTestState.getWorkflowTrace());
                        zipOut.write(serialized.getBytes(StandardCharsets.UTF_8));
                    } catch (Exception e) {
                        LOGGER.error(
                                "Failed to serialize State ({}, {})",
                                stateContainer.getTestMethod().getName(),
                                tlsTestState.getUuid(),
                                e);
                        errorMsg.append("\nFailed to serialize WorkflowTraces");
                        errorMsg.append(ExecptionPrinter.stacktraceToString(e));
                    }
                }
                zipOut.close();
                fos.close();
            } catch (Exception e) {
                LOGGER.error("", e);
            }
        }
        try {
            String err = errorMsg.toString();
            if (!err.isEmpty()) {
                FileWriter fileWriter =
                        new FileWriter(Paths.get(targetFolder, "_error.txt").toString());
                PrintWriter printWriter = new PrintWriter(fileWriter);
                printWriter.print(err);
                printWriter.close();
            }
        } catch (Exception ignored) {
        }
    }
}
