package de.rub.nds.tlstest.framework;

import static org.junit.Assert.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class ValidatorTest {

    Context context;
    TlsContext tlsContext;
    Record encryptedRecord;

    @BeforeEach
    void setUp() {
        Config config = new Config();
        context = new Context(new State(), config.getDefaultServerConnection());
        tlsContext = context.getTlsContext();
        tlsContext.setSelectedProtocolVersion(ProtocolVersion.TLS13);
        tlsContext.setSelectedCipherSuite(CipherSuite.TLS_AES_128_GCM_SHA256);
        encryptedRecord = new Record();
        encryptedRecord.setCompleteRecordBytes(
                ArrayConverter.hexStringToByteArray(
                        "1703030013a183a1b12be718f06b1aba21d8fc66449310f1"));
        encryptedRecord.setProtocolMessageBytes(
                ArrayConverter.hexStringToByteArray("a183a1b12be718f06b1aba21d8fc66449310f1"));
        encryptedRecord.setProtocolVersion(ProtocolVersion.TLS12.getValue());
        encryptedRecord.setLength(19);
        encryptedRecord.setContentType(ProtocolMessageType.APPLICATION_DATA.getValue());
        tlsContext.setServerHandshakeTrafficSecret(
                ArrayConverter.hexStringToByteArray(
                        "FE2A540F0B4185D0E3FED1A55B362C22DB94BD82D87A7FE69D1FFBBC7C554A45"));
        tlsContext.setClientHandshakeTrafficSecret(
                ArrayConverter.hexStringToByteArray(
                        "80D7BC469D311F154AB3F2E5A2B92E92E0DAD754CCB900BA4E9EE1922673E1CE"));
    }

    @Test
    void testTryToDecryptRecordWithHandshakeSecrets() {
        AlertMessage alert =
                Validator.tryToDecryptRecordWithHandshakeSecrets(tlsContext, encryptedRecord);
        assertNotNull(alert);
        assertEquals((byte) 0, alert.getDescription().getValue().byteValue());
        assertEquals((byte) 1, alert.getLevel().getValue().byteValue());
    }
}
