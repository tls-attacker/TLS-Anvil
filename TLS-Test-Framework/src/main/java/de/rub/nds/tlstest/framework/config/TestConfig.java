package de.rub.nds.tlstest.framework.config;

import com.beust.jcommander.Parameter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.TLSDelegateConfig;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlstest.framework.config.delegates.TestClientDelegate;
import de.rub.nds.tlstest.framework.config.delegates.TestServerDelegate;
import de.rub.nds.tlstest.framework.constants.TestEndpointType;
import org.bouncycastle.util.IPAddress;

import java.util.ArrayList;
import java.util.List;


public class TestConfig extends TLSDelegateConfig {

    private TestClientDelegate testClientDelegate = null;
    private TestServerDelegate testServerDelegate = null;

    private TestEndpointType testEndpointMode = null;


    @Parameter(names = "-tags", description = "Run only tests containing on of the specified tags", variableArity = true)
    private List<String> tags = new ArrayList<>();

    @Parameter(names = "-testPackage", description = "Run only tests included in the specified package")
    private String testPackage = null;


    public TestConfig() {
        super(new GeneralDelegate());
    }


    public TestEndpointType getTestEndpointMode() {
        return testEndpointMode;
    }

    public void setTestEndpointMode(TestEndpointType testEndpointMode) {
        this.testEndpointMode = testEndpointMode;
    }

    public void setTestEndpointMode(String testEndpointMode) {
        if (testEndpointMode.toLowerCase().equals("client")) {
            this.testEndpointMode = TestEndpointType.CLIENT;
        }
        else if (testEndpointMode.toLowerCase().equals("server")) {
            this.testEndpointMode = TestEndpointType.SERVER;
        }
        else {
            throw new RuntimeException("Invalid testEndpointMode");
        }
    }

    @Override
    public Config createConfig() {
        switch (this.testEndpointMode) {
            case CLIENT:
                addDelegate(this.testClientDelegate);
                break;
            case SERVER:
                addDelegate(this.testServerDelegate);
                break;
            default:
                throw new RuntimeException("Invalid testEndpointMode");
        }

        Config config = super.createConfig();

        if (!IPAddress.isValid(config.getDefaultClientConnection().getHostname()) || this.getTestServerDelegate().getSniHostname() != null) {
            config.setAddServerNameIndicationExtension(true);
        } else {
            config.setAddServerNameIndicationExtension(false);
        }

        return config;
    }

    public String getTestPackage() {
        return testPackage;
    }

    public List<String> getTags() {
        return tags;
    }

    public TestServerDelegate getTestServerDelegate() {
        return testServerDelegate;
    }

    public void setTestServerDelegate(TestServerDelegate testServerDelegate) {
        this.testServerDelegate = testServerDelegate;
    }

    public TestClientDelegate getTestClientDelegate() {
        return testClientDelegate;
    }

    public void setTestClientDelegate(TestClientDelegate testClientDelegate) {
        this.testClientDelegate = testClientDelegate;
    }
}
