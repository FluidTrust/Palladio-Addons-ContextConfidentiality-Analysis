package org.palladiosimulator.pcm.confidentiality.context.attackanalysis.execution.workflow.job;

import static org.palladiosimulator.pcm.confidentiality.context.attackanalysis.execution.partition.PartitionConstants.PARTITION_ID_CONTEXT;
import static org.palladiosimulator.pcm.confidentiality.context.attackanalysis.execution.partition.PartitionConstants.PARTITION_ID_PCM;

import org.eclipse.core.runtime.IProgressMonitor;
import org.eclipse.emf.common.util.URI;
import org.eclipse.emf.ecore.EPackage;
import org.palladiosimulator.analyzer.workflow.blackboard.PCMResourceSetPartition;
import org.palladiosimulator.analyzer.workflow.configurations.AbstractPCMWorkflowRunConfiguration;
import org.palladiosimulator.pcm.confidentiality.context.ContextPackage;
import org.palladiosimulator.pcm.confidentiality.context.attackanalysis.execution.partition.ContextPartition;
import org.palladiosimulator.pcm.confidentiality.context.attackanalysis.execution.workflow.config.ContextAnalysisWorkflowConfig;

import de.uka.ipd.sdq.workflow.jobs.CleanupFailedException;
import de.uka.ipd.sdq.workflow.jobs.IBlackboardInteractingJob;
import de.uka.ipd.sdq.workflow.jobs.JobFailedException;
import de.uka.ipd.sdq.workflow.jobs.UserCanceledException;
import de.uka.ipd.sdq.workflow.mdsd.blackboard.MDSDBlackboard;
import de.uka.ipd.sdq.workflow.mdsd.blackboard.ResourceSetPartition;

/**
 * Job for loading the required models for an Attacker Analysis into a MDSDBlackboard
 * 
 * @author majuwa
 *
 */
public abstract class AbstractLoadModelJob implements IBlackboardInteractingJob<MDSDBlackboard> {
    protected MDSDBlackboard blackboard;
    protected ContextAnalysisWorkflowConfig configuration;

    public AbstractLoadModelJob(ContextAnalysisWorkflowConfig configuration) {
        this.configuration = configuration;
    }

    protected void loadModel2Partition(ResourceSetPartition partition, URI[] uris, EPackage[] packages,
            String partitionID) {
        partition.initialiseResourceSetEPackages(packages);
        this.blackboard.addPartition(partitionID, partition);
        for (URI uri : uris)
            partition.loadModel(uri);
        partition.resolveAllProxies();
    }

    @Override
    public void cleanup(IProgressMonitor monitor) throws CleanupFailedException {
        //so far empty
    }

    @Override
    public void setBlackboard(MDSDBlackboard blackboard) {
        this.blackboard = blackboard;
    }

}
