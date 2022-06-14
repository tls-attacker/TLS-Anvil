/*
 *  TLS-Test-Framework - A framework for modeling TLS tests
 *
 *  Copyright 2020 Ruhr University Bochum and
 *  TÜV Informationstechnik GmbH
 *
 *  Licensed under Apache License 2.0
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

package de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionsConfig;

import java.util.IllegalFormatException;

/**
 * Represents a range of ports. The class can parse a string in form '[Min Port]-[Max Port]'. E.g. '123-456' represents
 * the ports 123,124,...,456.
 */
public class PortRange{
    private final Integer minPort;
    private final Integer maxPort;

    public PortRange(Integer minPort, Integer maxPort){
        if(maxPort < minPort){
            throw new IllegalArgumentException("Invalid PortRange. maxPort must not be smaller than minPort.");
        }

        if(minPort < 0 || maxPort > 65535){
            throw new IllegalArgumentException("Illegal port range. Ports can only be defined in between 0-65535");
        }

        this.minPort = minPort;
        this.maxPort = maxPort;
    }

    public Integer getMinPort() {
        return minPort;
    }

    public Integer getMaxPort() {
        return maxPort;
    }

    public boolean inRange(Integer port){
        return (port >= minPort && port <= maxPort);
    }

    /**
     * Parses a port range of format: '[Min Port]-[Max Port]', e.g. '4433-4444'.
     * the column ':' is also an allowed separator.
     *
     * @param str - the string to parse
     * @return the port range
     */
    public static PortRange fromString(String str){
        str = str.replace(":","-");
        String[] splittedStr = str.split("-");

        if(splittedStr.length != 2){
            throw new IllegalArgumentException("Illegal port range format. Syntax is \"[Min Port]-[Max Port]\"");
        }
        int minPort;
        int maxPort;
        try{
            minPort = Integer.parseInt(splittedStr[0]);
            maxPort = Integer.parseInt(splittedStr[1]);
        }
        catch(IllegalFormatException e){
            throw new IllegalArgumentException("Illegal port range format. Syntax is \"[Min Port]-[Max Port]\". " +
                    "Min and max port must be numbers.");
        }

        if(maxPort < minPort){
            throw new IllegalArgumentException("Illegal port range format. Syntax is \"[Min Port]-[Max Port]\". " +
                    "Max port must not be smaller than min port.");
        }

        return new PortRange(minPort, maxPort);
    }

    @Override
    public boolean equals(Object o) {
        if(o.getClass() != this.getClass()){
            return false;
        }
        PortRange other = (PortRange) o;
        return (this.minPort.equals(other.minPort) && this.maxPort.equals(other.maxPort));
    }

}
