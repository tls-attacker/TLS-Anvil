package de.rub.nds.tlstest.framework.annotations;


import de.rub.nds.tlstest.framework.constants.TestEndpointType;
import org.junit.jupiter.api.Tag;

import java.lang.annotation.*;

@Inherited
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD, ElementType.TYPE})
@TestEndpoint(endpoint = TestEndpointType.SERVER)
@Tag("server")
@TlsTest
public @interface ServerTest {

}
