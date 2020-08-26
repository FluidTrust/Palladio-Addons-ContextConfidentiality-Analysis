package org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow;

import org.apache.log4j.Logger;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.config.AttackerAnalyisWorkflowConfig;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.job.AttackerAnalysisJob;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.job.LoadContextJob;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.job.LoadPCMAttack;

import de.uka.ipd.sdq.workflow.jobs.SequentialBlackboardInteractingJob;
import de.uka.ipd.sdq.workflow.mdsd.blackboard.MDSDBlackboard;

/**
 * Workflow for AttackerAnalysis
 * 
 * @author majuwa
 * 
 *
 */
public class AttackerAnalysisWorkflow extends SequentialBlackboardInteractingJob<MDSDBlackboard> {
    private static final Logger LOGGER = Logger.getLogger(AttackerAnalysisWorkflow.class);
    public AttackerAnalysisWorkflow(AttackerAnalyisWorkflowConfig config) {
        super(false);
        this.add(new LoadPCMAttack(config));
        this.add(new LoadContextJob(config));
        this.add(new AttackerAnalysisJob(config));
    }
}
