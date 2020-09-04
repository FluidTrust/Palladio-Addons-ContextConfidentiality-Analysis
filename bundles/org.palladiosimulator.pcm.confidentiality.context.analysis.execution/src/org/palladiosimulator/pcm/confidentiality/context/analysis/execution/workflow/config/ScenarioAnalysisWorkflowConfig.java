package org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.config;

import org.eclipse.emf.common.util.URI;

public class ScenarioAnalysisWorkflowConfig extends ContextAnalysisWorkflowConfig {
    private URI usage;

    public URI getUsage() {
        return this.usage;
    }

    public void setUsage(final URI usage) {
        this.usage = usage;
    }

}
