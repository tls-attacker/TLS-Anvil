/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.anvil;

import com.fasterxml.jackson.annotation.JsonProperty;
import de.rub.nds.anvilcore.context.AnvilContext;
import de.rub.nds.anvilcore.context.AnvilTestConfig;
import de.rub.nds.anvilcore.teststate.AnvilTestCase;
import de.rub.nds.anvilcore.teststate.TestResult;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.utils.ExecptionPrinter;
import jakarta.xml.bind.DatatypeConverter;
import java.io.EOFException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;
import java.util.concurrent.TimeoutException;
import java.util.function.Consumer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;

public class TlsTestCase extends AnvilTestCase {
    private static final Logger LOGGER = LogManager.getLogger();
    private State state;
    private Integer srcPort = null;
    private Integer dstPort = null;

    private TlsTestCase() {}

    private String temporaryPcapFileName;
    private static int pcapFileCounter = 0;

    public String getTemporaryPcapFileName() {
        return temporaryPcapFileName;
    }

    public TlsTestCase(
            ExtensionContext context, State state, TlsParameterCombination parameterCombination) {
        super(parameterCombination, context);
        this.state = state;
        // set temporary file name counting up - gets renamed in finalizeAnvilTestCase()
        this.temporaryPcapFileName = String.format("tmp_%s.pcap", TlsTestCase.pcapFileCounter);
        TlsTestCase.pcapFileCounter += 1;
    }

    @Override
    public void finalizeAnvilTestCase() {
        finalizePacketCapture();
    }

    public void finalizePacketCapture() {
        AnvilTestConfig anvilConfig = AnvilContext.getInstance().getConfig();
        if (anvilConfig.isDisableTcpDump()) {
            return;
        }
        // filter the pcap files according to used ports and save them with their uuid
        Path basePath =
                Paths.get(
                        anvilConfig.getOutputFolder(),
                        "results",
                        this.getAssociatedContainer().getTestId());
        Path temporaryPcapPath = basePath.resolve(this.getTemporaryPcapFileName());
        if (!temporaryPcapPath.toFile().exists()) {
            LOGGER.error("No temporary pcap file found for testcase.");
            return;
        }
        Path finalPcapPath = basePath.resolve(String.format("dump_%s.pcap", this.getUuid()));
        try (PcapHandle pcapHandle = Pcaps.openOffline(temporaryPcapPath.toString())) {
            setPacketFilter(pcapHandle);
            dumpFilteredPacketsToFile(pcapHandle, finalPcapPath);
        } catch (PcapNativeException | NotOpenException e) {
            LOGGER.error("Error filtering pcap dump: ", e);
        }
        cleanupTemporaryPacketFiles(temporaryPcapPath);
        return;
    }

    private void cleanupTemporaryPacketFiles(Path temporaryPcapPath) {
        try {
            Files.delete(temporaryPcapPath);
        } catch (IOException e) {
            LOGGER.error("Error deleting temporary pcap dump file: ", e);
        }
    }

    private void dumpFilteredPacketsToFile(final PcapHandle pcapHandle, Path finalPcapPath)
            throws NotOpenException, PcapNativeException {
        PcapDumper pcapDumper = pcapHandle.dumpOpen(finalPcapPath.toString());
        while (true) {
            try {
                Packet p = pcapHandle.getNextPacketEx();
                if (p != null) {
                    pcapDumper.dump(p, pcapHandle.getTimestamp());
                }
            } catch (EOFException e) {
                // break on end of file
                break;
            } catch (TimeoutException e) {
                LOGGER.error("Error during filtering of pcap files: ", e);
            }
        }
        pcapDumper.close();
    }

    private void setPacketFilter(final PcapHandle pcapHandle)
            throws PcapNativeException, NotOpenException {
        if (this.getSrcPort() != null && this.getSrcPort() != -1) {
            pcapHandle.setFilter(
                    String.format(
                            TlsPcapCapturingInvocationInterceptor.resolveTransportProtocolPrefix(
                                            TestContext.getInstance().getConfig())
                                    + " port %s",
                            this.getSrcPort().toString()),
                    BpfProgram.BpfCompileMode.OPTIMIZE);
        } else if (this.getSrcPort() == -1) {
            LOGGER.info(
                    "Unable to fetch port from DatagramSocket for packet filter as socket is in closed state");
        }
    }

    public State getState() {
        return state;
    }

    public void setState(State state) {
        this.state = state;
    }

    public void validateFinal(Consumer<TlsTestCase> validateFunction) {
        // Todo: move to WorkflowRunner?
        try {
            validateFunction.accept(this);
            if (getTestResult() == TestResult.NOT_SPECIFIED) {
                setTestResult(TestResult.STRICTLY_SUCCEEDED);
            }
        } catch (Throwable err) {
            if (state.getExecutionException() != null) {
                err.addSuppressed(state.getExecutionException());
            }

            if (state.getTlsContext().isReceivedTransportHandlerException()) {
                addAdditionalResultInfo("Received TransportHandler exception");
            }

            setFailedReason(err);
            throw err;
        }
    }

    @JsonProperty("Stacktrace")
    public String getStacktrace() {
        if (getFailedReason() != null) {
            return ExecptionPrinter.stacktraceToString(getFailedReason());
        }
        return null;
    }

    public WorkflowTrace getWorkflowTrace() {
        if (state != null) {
            return state.getWorkflowTrace();
        }
        return null;
    }

    @JsonProperty("uuid")
    public String getUuid() {
        StringBuilder toHash = new StringBuilder();
        toHash.append(this.getAdditionalTestInformation());
        if (getParameterCombination() != null) {
            toHash.append(this.getParameterCombination().toString());
        }
        toHash.append(getAssociatedContainer().getTestClass().getName());
        toHash.append(getAssociatedContainer().getTestMethod().getName());

        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(toHash.toString().getBytes(StandardCharsets.UTF_8));
            return DatatypeConverter.printHexBinary(hash);
        } catch (Exception e) {
            throw new RuntimeException("SHA-256 not possible...");
        }
    }

    @JsonProperty("StartTimestamp")
    public String getStartTimestamp() {
        if (state == null) return null;
        SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSXXX");
        format.setTimeZone(TimeZone.getTimeZone("UTC"));
        return format.format(new Date(state.getStartTimestamp()));
    }

    @JsonProperty("EndTimestamp")
    public String getEndTimestamp() {
        if (state == null) return null;
        SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSXXX");
        format.setTimeZone(TimeZone.getTimeZone("UTC"));
        return format.format(new Date(state.getEndTimestamp()));
    }

    @JsonProperty("SrcPort")
    public Integer getSrcPort() {
        return srcPort;
    }

    @JsonProperty("DstPort")
    public Integer getDstPort() {
        return dstPort;
    }

    public void setSrcPort(Integer srcPort) {
        this.srcPort = srcPort;
    }

    public void setDstPort(Integer dstPort) {
        this.dstPort = dstPort;
    }
}
