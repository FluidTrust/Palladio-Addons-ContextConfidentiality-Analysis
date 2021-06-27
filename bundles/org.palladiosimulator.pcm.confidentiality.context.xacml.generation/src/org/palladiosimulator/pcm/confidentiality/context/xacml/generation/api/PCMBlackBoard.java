package org.palladiosimulator.pcm.confidentiality.context.xacml.generation.api;

import org.palladiosimulator.pcm.repository.Repository;
import org.palladiosimulator.pcm.resourceenvironment.ResourceEnvironment;
import org.palladiosimulator.pcm.system.System;

/**
 * Exchange Object for storing the PCM models
 *
 * @author majuwa
 *
 */
public class PCMBlackBoard {
    private final System system;
    private final Repository repository;
    private final ResourceEnvironment resources;

    public PCMBlackBoard(final System system, final Repository repository, final ResourceEnvironment resources) {
        this.system = system;
        this.repository = repository;
        this.resources = resources;
    }

    public System getSystem() {
        return this.system;
    }

    public Repository getRepository() {
        return this.repository;
    }

    public ResourceEnvironment getResources() {
        return this.resources;
    }

}
