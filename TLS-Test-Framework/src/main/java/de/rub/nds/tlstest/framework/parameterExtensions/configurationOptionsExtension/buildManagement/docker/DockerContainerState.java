/*
 *  TLS-Test-Framework - A framework for modeling TLS tests
 *
 *  Copyright 2020 Ruhr University Bochum and
 *  TÜV Informationstechnik GmbH
 *
 *  Licensed under Apache License 2.0
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

package de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.buildManagement.docker;

/**
 * Represents a docker container state.
 */
public enum DockerContainerState{
    /** The container is not yet started or was stopped.*/
    NOT_RUNNING,
    /** The container is paused.*/
    PAUSED,
    /** The container is running, i.e. not stopped or paused.*/
    RUNNING,
    /** The container does not exist or must not be accessed.*/
    INVALID
}
