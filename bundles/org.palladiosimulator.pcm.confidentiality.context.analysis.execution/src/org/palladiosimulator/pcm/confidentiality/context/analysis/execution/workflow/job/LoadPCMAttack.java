package org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.job;

import org.eclipse.emf.common.util.URI;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.config.AbstractAttackerAnalysisWorkflowConfig;

/**
 * Loads the necessary PCM models for the attacker analysis
 *
 * @author majuwa
 *
 */
public class LoadPCMAttack extends LoadPCMJob {

    public LoadPCMAttack(final AbstractAttackerAnalysisWorkflowConfig configuration) {
        super(configuration);
    }

    @Override
    protected URI[] getUrisPCM() {
        final var configuration = (AbstractAttackerAnalysisWorkflowConfig) this.configuration;
        return new URI[] { configuration.getRepositoryModel(), configuration.getAllocationModel() };
    }

}
