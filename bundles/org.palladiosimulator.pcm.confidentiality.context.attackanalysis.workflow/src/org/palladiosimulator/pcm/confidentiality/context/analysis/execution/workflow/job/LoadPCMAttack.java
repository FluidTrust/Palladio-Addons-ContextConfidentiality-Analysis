package org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.job;

import org.eclipse.emf.common.util.URI;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.config.AttackerAnalyisWorkflowConfig;

public class LoadPCMAttack extends LoadPCMJob {

    public LoadPCMAttack(AttackerAnalyisWorkflowConfig configuration) {
        super(configuration);
    }

    @Override
    protected URI[] getUrisPCM() {
        var configuration = (AttackerAnalyisWorkflowConfig) this.configuration;
        return  new URI[] { configuration.getRepositoryModel(), configuration.getAllocationModel()};
    }

}
