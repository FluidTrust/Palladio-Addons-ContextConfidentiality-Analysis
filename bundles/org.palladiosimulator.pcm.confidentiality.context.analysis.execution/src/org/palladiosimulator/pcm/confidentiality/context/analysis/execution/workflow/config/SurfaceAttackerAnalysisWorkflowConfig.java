package org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.config;

import org.eclipse.debug.core.ILaunch;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.AttackSurfaceAnalysisWorkflow;

import de.uka.ipd.sdq.workflow.jobs.IJob;

public class SurfaceAttackerAnalysisWorkflowConfig extends AbstractAttackerAnalysisWorkflowConfig {
    @Override
    public IJob createWorkflowJob(final ILaunch launch) {
        return new AttackSurfaceAnalysisWorkflow(this);
    }
}
