package de.rub.nds.tlstest.framework.utils;

import java.io.PrintWriter;
import java.io.StringWriter;

public class ExecptionPrinter {

    public static String stacktraceToString(Throwable e) {
        StringWriter sw = new StringWriter();
        e.printStackTrace(new PrintWriter(sw));
        return sw.toString();
    }
}
