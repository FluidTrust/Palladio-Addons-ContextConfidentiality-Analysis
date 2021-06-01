package org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow;

import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.config.ScenarioAnalysisWorkflowConfig;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.job.LoadContextJob;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.job.LoadPCMScenario;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.job.SaveOutputModelJob;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.job.ScenarioAnalysisJob;

import de.uka.ipd.sdq.workflow.jobs.SequentialBlackboardInteractingJob;
import de.uka.ipd.sdq.workflow.mdsd.blackboard.MDSDBlackboard;

/**
 * Workflow for AttackerAnalysis
 *
 * @author majuwa
 *
 *
 */
public class ScenarioAnalysisWorkflow extends SequentialBlackboardInteractingJob<MDSDBlackboard> {
    

    public ScenarioAnalysisWorkflow(final ScenarioAnalysisWorkflowConfig config) {
        super(false);
        this.add(new LoadPCMScenario(config));
        this.add(new LoadContextJob(config));
        this.add(new ScenarioAnalysisJob(config));
        this.add(new SaveOutputModelJob(config));
    }
}
