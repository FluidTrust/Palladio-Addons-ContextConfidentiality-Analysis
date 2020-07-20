package org.palladiosimulator.pcm.confidentiality.context.attackanalysis.execution.workflow.job;

import static org.palladiosimulator.pcm.confidentiality.context.attackanalysis.execution.partition.PartitionConstants.PARTITION_ID_CONTEXT;
import static org.palladiosimulator.pcm.confidentiality.context.attackanalysis.execution.partition.PartitionConstants.PARTITION_ID_PCM;
import static org.palladiosimulator.pcm.confidentiality.context.attackanalysis.execution.partition.PartitionConstants.PARTITION_ID_KASTEL;

import org.eclipse.core.runtime.IProgressMonitor;
import org.palladiosimulator.analyzer.workflow.blackboard.PCMResourceSetPartition;
import org.palladiosimulator.pcm.confidentiality.context.attackanalysis.execution.Activator;
import org.palladiosimulator.pcm.confidentiality.context.attackanalysis.execution.partition.ContextPartition;
import org.palladiosimulator.pcm.confidentiality.context.attackanalysis.execution.partition.DataAttackPartition;
import org.palladiosimulator.pcm.confidentiality.context.attackanalysis.execution.workflow.config.ContextAnalysisWorkflowConfig;
import org.palladiosimulator.pcm.confidentiality.context.attackanalysis.execution.workflow.config.ScenarioAnalysisWorkflowConfig;

import de.uka.ipd.sdq.workflow.jobs.CleanupFailedException;
import de.uka.ipd.sdq.workflow.jobs.IBlackboardInteractingJob;
import de.uka.ipd.sdq.workflow.jobs.JobFailedException;
import de.uka.ipd.sdq.workflow.jobs.UserCanceledException;
import de.uka.ipd.sdq.workflow.mdsd.blackboard.MDSDBlackboard;

/**
 * Job specification to launch an attacker analysis. Before using the models should be loaded into
 * the corresponding MDSDBlackboard
 * 
 * @author majuwa
 *
 */
public class ScenarioAnalysisJob implements IBlackboardInteractingJob<MDSDBlackboard> {

    private MDSDBlackboard blackbord;

    public ScenarioAnalysisJob(ScenarioAnalysisWorkflowConfig config) {

    }

    @Override
    public void execute(IProgressMonitor monitor) throws JobFailedException, UserCanceledException {
        var analysis = Activator.getInstance().getAnalysis();

        var contextPartition = (ContextPartition) this.blackbord.getPartition(PARTITION_ID_CONTEXT);
        var pcmPartition = (PCMResourceSetPartition) this.blackbord.getPartition(PARTITION_ID_PCM);
        var dataPartition = (DataAttackPartition) this.blackbord.getPartition(PARTITION_ID_KASTEL);

        analysis.runAttackerAnalysis(pcmPartition.getMiddlewareRepository(), contextPartition.getContextSpecification(),
                null);
    }

    @Override
    public void cleanup(IProgressMonitor monitor) throws CleanupFailedException {
        // TODO Provide clean up Operations

    }

    @Override
    public String getName() {
        return "Scenario Analysis Job";
    }

    @Override
    public void setBlackboard(MDSDBlackboard blackboard) {
        this.blackbord = blackboard;
    }
}
