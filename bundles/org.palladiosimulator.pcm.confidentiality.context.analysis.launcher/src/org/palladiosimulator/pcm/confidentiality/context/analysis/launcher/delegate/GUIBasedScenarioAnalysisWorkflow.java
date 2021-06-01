package org.palladiosimulator.pcm.confidentiality.context.analysis.launcher.delegate;

import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.ScenarioAnalysisWorkflow;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.config.ScenarioAnalysisWorkflowConfig;

public class GUIBasedScenarioAnalysisWorkflow extends ScenarioAnalysisWorkflow {
    public GUIBasedScenarioAnalysisWorkflow(final ScenarioAnalysisWorkflowConfig config) {
        super(config);
        this.add(new OutputScenarioJob());
    }
}
