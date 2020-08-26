package org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.job;

import static org.palladiosimulator.pcm.confidentiality.context.analysis.execution.partition.PartitionConstants.PARTITION_ID_PCM;

import org.eclipse.core.runtime.IProgressMonitor;
import org.eclipse.emf.common.util.URI;
import org.palladiosimulator.analyzer.workflow.blackboard.PCMResourceSetPartition;
import org.palladiosimulator.analyzer.workflow.configurations.AbstractPCMWorkflowRunConfiguration;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.config.ContextAnalysisWorkflowConfig;

import de.uka.ipd.sdq.workflow.jobs.JobFailedException;
import de.uka.ipd.sdq.workflow.jobs.UserCanceledException;

public abstract class LoadPCMJob extends AbstractLoadModelJob{

    public LoadPCMJob(ContextAnalysisWorkflowConfig configuration) {
        super(configuration);
    }
    @Override
    public void execute(IProgressMonitor monitor) throws JobFailedException, UserCanceledException {
        var pcmPartition = new PCMResourceSetPartition();
        var urisPCM =  getUrisPCM();
        loadModel2Partition(pcmPartition, urisPCM, AbstractPCMWorkflowRunConfiguration.PCM_EPACKAGES, PARTITION_ID_PCM);
    }
    @Override
    public String getName() {
       return "Load PCM model";
    }
    
    protected abstract URI[] getUrisPCM();

}
