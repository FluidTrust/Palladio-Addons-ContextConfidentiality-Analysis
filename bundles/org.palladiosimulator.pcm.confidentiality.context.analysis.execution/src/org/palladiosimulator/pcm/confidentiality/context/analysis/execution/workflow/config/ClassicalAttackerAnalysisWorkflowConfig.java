package org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.config;

import org.eclipse.debug.core.ILaunch;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.ClassicalAttackerAnalysisWorkflow;

import de.uka.ipd.sdq.workflow.jobs.IJob;

public class ClassicalAttackerAnalysisWorkflowConfig extends AbstractAttackerAnalysisWorkflowConfig {
    @Override
    public IJob createWorkflowJob(final ILaunch launch) {
        return new ClassicalAttackerAnalysisWorkflow(this);
    }
}
