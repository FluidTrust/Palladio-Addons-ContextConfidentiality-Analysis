package org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow;

import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.config.ScenarioAnalysisWorkflowConfig;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.job.OutputScenarioJob;

public class GUIBasedScenarioAnalysisWorkflow extends ScenarioAnalysisWorkflow {
    public GUIBasedScenarioAnalysisWorkflow(final ScenarioAnalysisWorkflowConfig config) {
        super(config);
        this.add(new OutputScenarioJob());
    }
}
