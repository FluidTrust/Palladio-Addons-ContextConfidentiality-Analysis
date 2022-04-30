package org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow;

import static org.palladiosimulator.pcm.confidentiality.context.analysis.execution.partition.PartitionConstants.PARTITION_ID_MODIFICATION;

import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.config.SurfaceAttackerAnalysisWorkflowConfig;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.job.AttackSurfaceAnalysisJob;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.job.LoadAttackerModel;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.job.LoadContextJob;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.job.LoadModificationMarkJob;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.job.LoadPCMAttack;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.job.VulnerabilityRollOutComponentsJob;

import de.uka.ipd.sdq.workflow.jobs.SequentialBlackboardInteractingJob;
import de.uka.ipd.sdq.workflow.mdsd.blackboard.MDSDBlackboard;
import de.uka.ipd.sdq.workflow.mdsd.blackboard.SavePartitionToDiskJob;

/**
 * Workflow for AttackSurfaceAnalysis
 *
 * @author majuwa
 * @author ugnwq
 */
public class AttackSurfaceAnalysisWorkflow extends SequentialBlackboardInteractingJob<MDSDBlackboard> {

    public AttackSurfaceAnalysisWorkflow(final SurfaceAttackerAnalysisWorkflowConfig config) {
        super(false);
        this.add(new LoadPCMAttack(config));
        this.add(new LoadContextJob(config));
        this.add(new LoadAttackerModel(config));
        this.add(new LoadModificationMarkJob(config));
        this.add(new VulnerabilityRollOutComponentsJob());
        this.add(new AttackSurfaceAnalysisJob(config));
        this.add(new SavePartitionToDiskJob(PARTITION_ID_MODIFICATION));
    }
}
