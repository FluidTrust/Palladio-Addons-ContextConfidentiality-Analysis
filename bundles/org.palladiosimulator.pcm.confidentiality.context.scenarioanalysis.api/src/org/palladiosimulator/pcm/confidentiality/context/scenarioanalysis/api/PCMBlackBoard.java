package org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.api;

import org.palladiosimulator.pcm.repository.Repository;
import org.palladiosimulator.pcm.usagemodel.UsageModel;
import org.palladiosimulator.pcm.system.System;

/**
 * Exchange Object for storing the PCM models
 * @author majuwa
 *
 */
public class PCMBlackBoard {
    private System system;
    private Repository repository;
    private UsageModel usageModel;
    public PCMBlackBoard(System system, Repository repository, UsageModel usageModel) {
        super();
        this.system = system;
        this.repository = repository;
        this.usageModel = usageModel;
    }
    public System getSystem() {
        return system;
    }
    public Repository getRepository() {
        return repository;
    }
    public UsageModel getUsageModel() {
        return usageModel;
    }

}
