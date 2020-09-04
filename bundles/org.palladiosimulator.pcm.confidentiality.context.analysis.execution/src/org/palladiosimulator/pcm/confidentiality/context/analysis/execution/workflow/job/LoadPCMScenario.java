package org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.job;

import org.eclipse.emf.common.util.URI;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.config.ScenarioAnalysisWorkflowConfig;

public class LoadPCMScenario extends LoadPCMJob {

    public LoadPCMScenario(final ScenarioAnalysisWorkflowConfig configuration) {
        super(configuration);
    }

    @Override
    protected URI[] getUrisPCM() {
        final var configuration = (ScenarioAnalysisWorkflowConfig) this.configuration;
        return new URI[] { configuration.getRepositoryModel(), configuration.getAllocationModel(),
                configuration.getUsage() };
    }

}
