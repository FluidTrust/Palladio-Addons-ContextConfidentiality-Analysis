package org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow;

import static org.palladiosimulator.pcm.confidentiality.context.analysis.execution.partition.PartitionConstants.PARTITION_ID_MODIFICATION;

import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.config.AttackerAnalysisWorkflowConfig;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.job.AttackSurfaceAnalysisJob;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.job.LoadAttackerModel;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.job.LoadContextJob;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.job.LoadModifacationMarkJob;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.job.LoadPCMAttack;

import de.uka.ipd.sdq.workflow.jobs.SequentialBlackboardInteractingJob;
import de.uka.ipd.sdq.workflow.mdsd.blackboard.MDSDBlackboard;
import de.uka.ipd.sdq.workflow.mdsd.blackboard.SavePartitionToDiskJob;

/**
 * Workflow for AttackerAnalysis
 *
 * @author majuwa
 *
 *
 */
public class AttackSurfaceAnalysisWorkflow extends SequentialBlackboardInteractingJob<MDSDBlackboard> {

    public AttackSurfaceAnalysisWorkflow(final AttackerAnalysisWorkflowConfig config) {
        super(false);
        this.add(new LoadPCMAttack(config));
        this.add(new LoadContextJob(config));
        this.add(new LoadAttackerModel(config));
        this.add(new LoadModifacationMarkJob(config));
        this.add(new AttackSurfaceAnalysisJob(config));
        this.add(new SavePartitionToDiskJob(PARTITION_ID_MODIFICATION));
    }
}
