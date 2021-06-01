package org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.job;

import static org.palladiosimulator.pcm.confidentiality.context.analysis.execution.partition.PartitionConstants.PARTITION_ID_ATTACK;

import org.eclipse.core.runtime.IProgressMonitor;
import org.eclipse.emf.common.util.URI;
import org.eclipse.emf.ecore.EPackage;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.AttackerPackage;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.partition.AttackPartition;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.config.AttackerAnalysisWorkflowConfig;

import de.uka.ipd.sdq.workflow.jobs.JobFailedException;
import de.uka.ipd.sdq.workflow.jobs.UserCanceledException;

public class LoadAttackerModel extends AbstractLoadModelJob {

    public LoadAttackerModel(final AttackerAnalysisWorkflowConfig configuration) {
        super(configuration);
    }

    @Override
    public void execute(final IProgressMonitor monitor) throws JobFailedException, UserCanceledException {
        final var attackPartition = new AttackPartition();
        this.loadModel2Partition(attackPartition,
                new URI[] { ((AttackerAnalysisWorkflowConfig) this.configuration).getAttackModel() },
                new EPackage[] { AttackerPackage.eINSTANCE }, PARTITION_ID_ATTACK);
    }

    @Override
    public String getName() {
        return "Load attack model";
    }
}