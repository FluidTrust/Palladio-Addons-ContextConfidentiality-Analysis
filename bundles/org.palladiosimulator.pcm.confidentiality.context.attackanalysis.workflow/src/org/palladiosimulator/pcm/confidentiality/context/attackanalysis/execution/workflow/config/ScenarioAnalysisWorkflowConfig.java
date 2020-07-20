package org.palladiosimulator.pcm.confidentiality.context.attackanalysis.execution.workflow.config;

import org.palladiosimulator.pcm.usagemodel.UsageModel;

public class ScenarioAnalysisWorkflowConfig extends ContextAnalysisWorkflowConfig {
    private UsageModel usage;

    public UsageModel getUsage() {
        return usage;
    }

    public void setUsage(UsageModel usage) {
        this.usage = usage;
    }
    

}
