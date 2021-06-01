package org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.api;

import org.palladiosimulator.pcm.repository.Repository;
import org.palladiosimulator.pcm.system.System;
import org.palladiosimulator.pcm.usagemodel.UsageModel;

/**
 * Exchange Object for storing the PCM models
 *
 * @author majuwa
 *
 */
public class PCMBlackBoard {
    private final System system;
    private final Repository repository;
    private final UsageModel usageModel;

    public PCMBlackBoard(final System system, final Repository repository, final UsageModel usageModel) {
        super();
        this.system = system;
        this.repository = repository;
        this.usageModel = usageModel;
    }

    public System getSystem() {
        return this.system;
    }

    public Repository getRepository() {
        return this.repository;
    }

    public UsageModel getUsageModel() {
        return this.usageModel;
    }

}
