package org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.job;

import static org.palladiosimulator.pcm.confidentiality.context.analysis.execution.partition.PartitionConstants.PARTITION_ID_MODIFICATION;

import org.eclipse.core.runtime.IProgressMonitor;
import org.eclipse.emf.common.util.URI;
import org.eclipse.emf.ecore.EPackage;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.partition.ModificationMarkPartition;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.config.AttackerAnalysisWorkflowConfig;

import de.uka.ipd.sdq.workflow.jobs.JobFailedException;
import de.uka.ipd.sdq.workflow.jobs.UserCanceledException;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksPackage;

public class LoadModifacationMarkJob extends AbstractLoadModelJob {

    public LoadModifacationMarkJob(final AttackerAnalysisWorkflowConfig configuration) {
        super(configuration);
    }

    @Override
    public void execute(final IProgressMonitor monitor) throws JobFailedException, UserCanceledException {
        final var contextPartition = new ModificationMarkPartition();
        this.loadModel2Partition(contextPartition,
                new URI[] { ((AttackerAnalysisWorkflowConfig) this.configuration).getModificationModel() },
                new EPackage[] { KAMP4attackModificationmarksPackage.eINSTANCE }, PARTITION_ID_MODIFICATION);

    }

    @Override
    public String getName() {
        return "Load modifaction model";
    }

}
