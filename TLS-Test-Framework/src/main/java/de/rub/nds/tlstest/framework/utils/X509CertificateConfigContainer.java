package de.rub.nds.tlstest.framework.utils;

import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.constants.X509NamedCurve;
import de.rub.nds.x509attacker.constants.X509PublicKeyType;
import de.rub.nds.x509attacker.constants.X509SignatureAlgorithm;
import jakarta.xml.bind.*;
import java.io.*;
import java.math.BigInteger;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Stream;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class X509CertificateConfigContainer {
    private static X509CertificateConfigContainer instance = null;
    private static final Logger LOGGER = LogManager.getLogger();
    private ArrayList<X509CertificateConfig> certConfigs;
    public static final String RESOURCE_CERT_CONFIG_FOLDER = "/serverCertConfigs";

    public static X509CertificateConfigContainer getInstance() {
        if (instance == null) {
            instance = new X509CertificateConfigContainer();
        }
        return instance;
    }

    public List<X509CertificateConfig> getCertConfigs() {
        return certConfigs;
    }

    private X509CertificateConfig genRsa1024Cert() {
        // from: openssl rsa -in rsa1024_key.pem -text -noout
        X509CertificateConfig rsa1024 = new X509CertificateConfig();
        BigInteger rsaModulus =
                new BigInteger(
                        "00d7169ef864f41347e8af4886d7696a378a116baaf523e7c24d042ef3a0fef406f34a1547d2c2cd43dd6c431125de8066b56e7eebb5d7ee340c5cd0aa38fd7cbb22a52153b260c6a0219a3bc22d95209bb26a428306f9819dd0b824289b36a079f02e774fff17051086340bc52c49ad139f6cf55e7232d605222eec39a5178b6f",
                        16);

        BigInteger rsaPublicKey = new BigInteger("65537", 10);
        rsaPublicKey = new BigInteger("65537", 10);

        BigInteger rsaPrivateKey =
                new BigInteger(
                        "00ae6e84fbd2fb724b85f3e93099afbed94dda74e3cf2c903eae30ef56db41086c3e8fdd144363820e409b1504ea1e392992880adc63bbbb4d709d31086b717fddd2cdd86369731bf85c998881a403f277c884952111863aaf00c7179db55ae183387a8c18c5ec024f13e24704cd6dc1eaaa24477ffd2724d3f440d62479be2169",
                        16);

        rsa1024.setPublicKeyType(X509PublicKeyType.RSASSA_PSS);
        rsa1024.setRsaModulus(rsaModulus);
        rsa1024.setRsaPublicKey(rsaPublicKey);
        rsa1024.setRsaPrivateKey(rsaPrivateKey);
        // this.write(rsa1024, new File("path/rsa1024.xml"));
        return rsa1024;
    }

    private X509CertificateConfig genRsa2048CertConfig() {
        X509CertificateConfig rsa2048 = new X509CertificateConfig();

        BigInteger rsaModulus =
                new BigInteger(
                        "00ccb73b51ad7a40cc4ad79afab7211bbc7bee8cbbf0c598f7e28cd1394eecb06aa2d9f99cbc8d3757494694c0dc70d4418229223e06633164f5eca5616ab9d6858cb46883f9d6ddfc4f5a37fa8a3d23fad5b2554d7342eb9a644b03c36946c51c727fce66ee885114ff24c24a476307f05542b428c9b5651e6f060cb95297743650349f7178915a71bea4fe4bd18758b9b51a204f6083d9f6b8fae07591c5aeb0f01553a77c2d285ce2196f46e6604f73e9af79692da48dde5c5f31052c0b3c21b94d042e279a648bddb5f8d749b6f76a8c3af909111b1739b7ebf263e416e801dafa53ca19040e4a943a2978075ba59993a4a48419720b7d2a10fae909a67eb3",
                        16);
        BigInteger rsaPublicKey = new BigInteger("65537", 10);

        BigInteger rsaPrivateKey =
                new BigInteger(
                        "4020fe321df7f8288721776926c8f6595b316560d291f3d36362dd7fe85b79004eb79ddc1dacd7333ebf1f8633081d55d02276999b82a34c8f456ca151bf99960877d36dd46c1cea172999f3a02e7b00eec488b8546d18452b39dc99f076bcf4a661a714d3905c66096f4875e05b0377a41ddb3613ca013d416651c2143f61a5ba95ea82337fce5df16b710a9d0557b481243603432d88c6188c3f87a38030bd51c291d53615aa50653d377ce1bb73fb1c8199e78efa7a8f8259e5d1959ee357c0d7ec56ac29da544f56759171905583022c6780dd0c684525dc3745105f3d8ccf80947a3a954eec7d4778754f74f109610aad2b5a49f3e7cddcfdc4f5b55061",
                        16);

        // rsa2048.setPublicKeyType(X509PublicKeyType.RSASSA_PSS);
        // rsa2048.setPublicKeyType(X509PublicKeyType.RSASSA_PSS);
        rsa2048.setPublicKeyType(X509PublicKeyType.RSA);
        rsa2048.setRsaModulus(rsaModulus);
        rsa2048.setRsaPublicKey(rsaPublicKey);
        rsa2048.setRsaPrivateKey(rsaPrivateKey);
        // this.write(rsa2048, new File("path/rsa2048.xml"));
        return rsa2048;
    }

    private X509CertificateConfig genRsa4096CertConfig() {
        X509CertificateConfig rsa4096 = new X509CertificateConfig();

        BigInteger rsaModulus =
                new BigInteger(
                        "00c0876e609e9573e314a9052baebfc2c213b24007359987759c5b64272b1df16cc30274813d4ef1c63d1663edd169d551eeeb9529c707e20d48553c70b8e9f00f5555b77d0a595a5984ad7601879d06aab234ccecdb3e75c8c453c5da2ba905650e14f8447c3903652b9f00df0e345751fa872602207ab4b113b05a7c580109c81a27237eac44b144adb8bd86502cbccb8f459298360dbbe41dff35f5f70b70b00d28c7de1c58a6944b1533ce7b2fa6cea953b46e7d390d2d58e1ecb2738387f26b4921018d70f8b2be1ee6e4522a4271c9fb0466060455bdd586bec40d312f311e248785f13269c12e9ef19a0f10e4f9ffbba995c18d746d2cd64c3c958a3dafd240d948394c3f19bc62cffd8a643582aa3b4c646f0aeb364b9c4666df5d42caa267ee125b118babe33842ba696ffb141a1f2402072b56e5eb43f576d63b32db5d7347bf1aa5ddad42e49d0b190dc609fad7dbf0c8d0cc4f7523ce56b6ae9c4ca3142de742ba8911873e887cce1523c3edb36fa0b36e51f2b796b3199387b96f1d5aab9a4b39fe8d430d7e336b4d01fe4b25cc25b768986dbe86e24f7379b961fc368d6b23d9b97f24a01f19c5fcb75ba69055e45c5ede8381fef7b44f27a33f44863fb55080a92fcabc01888599171e1917b457224d4e3242b91d99985cf307ede657d9dffa7104f0bc033e7e733f80466372e1ddde8d0df0b0422500221511",
                        16);
        BigInteger rsaPublicKey = new BigInteger("65537", 10);

        BigInteger rsaPrivateKey =
                new BigInteger(
                        "336bf8af15ac1527b17cf3449787e01cb5e605f3e6fcfa910f11d9ce1c56030569905e4da6724f61032fd7c0cd0dd74beae44112c775f38a58a76b5d30064b77ccf2f7ef0db48fcd1902bb61ed36a37133e7a6541cbab1facd75128312e631eaabb82e171c969db187d510068364b76dcddc0aeac681ff80cc216e0987f7bf0512f72123d41f04b9b32c84723b37b7b526af0e58591791f77b8b8e7e035daadb5aa869b98918a4653728928db39926944be56f6b9346899e72fee4994500fc6e62f9453784ef877d360a4ae0f09118ee0b645fe85ff308738b7451bf4b46b7b406b8faf96b526bac8d2726a05f25c40281ab3dc021d20626a2b319e9948737b2277dde314eece01c1479d6a9ee95651295abb3856c75d783bae8cfff7e619eea2744033d155064f7e0c940b6bc2d24ccafbc7c5cce1a819b98d2b76310ab693b88910e6d042a787ca2320a2326a89e7b8d7ec4df89433b3ff5613cb04cc5ed0f9bf20d30ac81ab7c3cf592b64e03dc6e0733e00fd889d064d5ffcb8e3c5fec72bf48c1613346e9060c976b3b7e6cde0005ccc9ab60ae88d2ca427a571ce9aef36aa455781128d0badc08102ba8d2f875b3a31d06c634b9c3368c25e0e837b25fe3762ab9f4bcb7b4379f152eba07e39969ef73997982e5ba0863e623b76f79bb704a36c5c922f53e250d6400a602d34b5be1f81cd161e34a5614d2f561152381",
                        16);
        rsa4096.setPublicKeyType(X509PublicKeyType.RSA);
        // rsa4096.setPublicKeyType(X509PublicKeyType.RSASSA_PSS);
        rsa4096.setRsaModulus(rsaModulus);

        rsa4096.setDefaultIssuerRsaModulus(rsaModulus);
        rsa4096.setRsaPublicKey(rsaPublicKey);
        rsa4096.setRsaPrivateKey(rsaPrivateKey);
        // this.write(rsa4096, new File("path/rsa4096.xml"));
        return rsa4096;
    }

    private X509CertificateConfig geneEdsaCertConfig() {
        X509CertificateConfig ecdsa = new X509CertificateConfig();
        ecdsa.setPublicKeyType(X509PublicKeyType.ECDH_ECDSA);
        ecdsa.setSignatureAlgorithm(X509SignatureAlgorithm.ECDSA_WITH_SHA256);
        ecdsa.setDefaultSubjectNamedCurve(X509NamedCurve.SECP256R1);
        return ecdsa;
    }

    private X509CertificateConfig geneDhCertConfig() {
        X509CertificateConfig dh = new X509CertificateConfig();
        dh.setPublicKeyType(X509PublicKeyType.DH);
        return dh;
    }

    private X509CertificateConfigContainer() {
        certConfigs = new ArrayList<>();

        // TODO: remove programmatic certConf generation and parse CertConfigs from XML resources
        //  instead
        final boolean USE_HARDCODED_CERTS_FOR_DEBUGGING = true;
        if (USE_HARDCODED_CERTS_FOR_DEBUGGING) {
            LOGGER.warn("USE_HARDCODED_CERTS_FOR_DEBUGGING: true");
            certConfigs.add(genRsa2048CertConfig());
            certConfigs.add(genRsa4096CertConfig());
        } else {
            LOGGER.debug("parse certificates form resources");
            parseCertConfigsFromResources();
        }
    }

    private void parseCertConfigsFromResources() {
        URI uri = null;
        try {
            uri =
                    X509CertificateConfigContainer.class
                            .getResource(RESOURCE_CERT_CONFIG_FOLDER)
                            .toURI();
        } catch (URISyntaxException | NullPointerException e) {
            LOGGER.warn("No serverCertConfigs resource folder found.");
            return;
        }
        try (FileSystem fileSystem = FileSystems.newFileSystem(uri, Collections.emptyMap())) {
            Path folderRootPath = fileSystem.getPath(RESOURCE_CERT_CONFIG_FOLDER);
            Stream<Path> walk = Files.walk(folderRootPath, 1);
            walk.filter(childFileOrFolderPath -> Files.isRegularFile(childFileOrFolderPath))
                    .filter(filePath -> filePath.toString().endsWith("xml"))
                    .forEach(
                            xmlCertConfigPath -> {
                                InputStream is =
                                        X509CertificateConfigContainer.class.getResourceAsStream(
                                                xmlCertConfigPath.toString());
                                certConfigs.add(read(is));
                                LOGGER.info("Added certificate: {}", xmlCertConfigPath);
                            });
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void write(X509CertificateConfig config, OutputStream os) {
        ByteArrayOutputStream tempStream = new ByteArrayOutputStream();
        JAXB.marshal(config, tempStream);
        try {
            os.write(
                    tempStream
                            .toString()
                            .replaceAll("\r?\n", System.lineSeparator())
                            .getBytes(StandardCharsets.UTF_8));
        } catch (IOException ex) {
            throw new RuntimeException("Could not format XML");
        }
    }

    private void write(X509CertificateConfig config, File f) {
        try (FileOutputStream fs = new FileOutputStream(f)) {
            write(config, fs);
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        }
    }

    public static X509CertificateConfig read(InputStream stream) {
        try {
            Unmarshaller unmarshaller =
                    JAXBContext.newInstance(X509CertificateConfig.class).createUnmarshaller();
            // output any anomalies in the given config file
            unmarshaller.setEventHandler(
                    event -> {
                        // Raise an exception also on warnings
                        return false;
                    });
            return read(stream, unmarshaller);
        } catch (JAXBException e) {
            throw new RuntimeException(e);
        }
    }

    private static X509CertificateConfig read(InputStream stream, Unmarshaller unmarshaller) {
        if (stream == null) {
            throw new IllegalArgumentException("Stream cannot be null");
        }
        try {
            XMLInputFactory xif = XMLInputFactory.newFactory();
            xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
            xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
            XMLStreamReader xsr = xif.createXMLStreamReader(stream);
            return (X509CertificateConfig) unmarshaller.unmarshal(xsr);
        } catch (XMLStreamException | JAXBException e) {
            throw new RuntimeException(e);
        }
    }

    public static X509CertificateConfig read(File f) {
        try {
            Unmarshaller unmarshaller =
                    JAXBContext.newInstance(X509CertificateConfig.class).createUnmarshaller();
            // output any anomalies in the given config file
            unmarshaller.setEventHandler(
                    new ValidationEventHandler() {
                        @Override
                        public boolean handleEvent(ValidationEvent event) {
                            // Raise an exception also on warnings
                            return false;
                        }
                    });
            try (FileInputStream fis = new FileInputStream(f)) {
                return read(fis, unmarshaller);
            }
        } catch (JAXBException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new IllegalArgumentException("File cannot be read");
        }
    }
}
