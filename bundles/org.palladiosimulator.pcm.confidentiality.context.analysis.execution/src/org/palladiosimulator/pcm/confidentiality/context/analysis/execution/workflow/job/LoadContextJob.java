package org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.job;

import static org.palladiosimulator.pcm.confidentiality.context.analysis.execution.partition.PartitionConstants.PARTITION_ID_CONTEXT;

import org.eclipse.core.runtime.IProgressMonitor;
import org.eclipse.emf.common.util.URI;
import org.eclipse.emf.ecore.EPackage;
import org.palladiosimulator.pcm.confidentiality.context.ContextPackage;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.partition.ContextPartition;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.config.ContextAnalysisWorkflowConfig;

import de.uka.ipd.sdq.workflow.jobs.JobFailedException;
import de.uka.ipd.sdq.workflow.jobs.UserCanceledException;

public class LoadContextJob extends AbstractLoadModelJob {

    public LoadContextJob(final ContextAnalysisWorkflowConfig configuration) {
        super(configuration);
    }

    @Override
    public void execute(final IProgressMonitor monitor) throws JobFailedException, UserCanceledException {
        final var contextPartition = new ContextPartition();
        loadModel2Partition(contextPartition, new URI[] { this.configuration.getContextModel() },
                new EPackage[] { ContextPackage.eINSTANCE }, PARTITION_ID_CONTEXT);
    }

    @Override
    public String getName() {
        return "Load context model";
    }

}
