package org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.config;

import org.eclipse.debug.core.ILaunch;
import org.eclipse.emf.common.util.URI;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.GUIBasedScenarioAnalysisWorkflow;

import de.uka.ipd.sdq.workflow.jobs.IJob;

public class ScenarioAnalysisWorkflowConfig extends ContextAnalysisWorkflowConfig {
    private URI usage;

    public URI getUsage() {
        return this.usage;
    }

    public void setUsage(final URI usage) {
        this.usage = usage;
    }

    @Override
    public IJob createWorkflowJob(final ILaunch launch) {
        return new GUIBasedScenarioAnalysisWorkflow(this);
    }

}
