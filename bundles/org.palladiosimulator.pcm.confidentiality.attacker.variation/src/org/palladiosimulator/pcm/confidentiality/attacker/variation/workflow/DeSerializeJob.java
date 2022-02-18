package org.palladiosimulator.pcm.confidentiality.attacker.variation.workflow;

import org.eclipse.core.runtime.IProgressMonitor;
import org.palladiosimulator.pcm.confidentiality.attacker.variation.output.AttackerComponentPathDTO;
import org.palladiosimulator.pcm.confidentiality.attacker.variation.output.VariationOutputBlackBoard;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.partition.ModificationMarkPartition;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.partition.PartitionConstants;

import de.uka.ipd.sdq.workflow.jobs.CleanupFailedException;
import de.uka.ipd.sdq.workflow.jobs.IBlackboardInteractingJob;
import de.uka.ipd.sdq.workflow.jobs.JobFailedException;
import de.uka.ipd.sdq.workflow.jobs.UserCanceledException;

public class DeSerializeJob implements IBlackboardInteractingJob<VariationOutputBlackBoard> {
    private VariationOutputBlackBoard blackboard;

    @Override
    public void execute(IProgressMonitor monitor) throws JobFailedException, UserCanceledException {
        final var modificationPartition = ((ModificationMarkPartition) this.blackboard
                .getPartition(PartitionConstants.PARTITION_ID_MODIFICATION)).getModificationRepository();



        this.blackboard.setAttackerPath(new AttackerComponentPathDTO(modificationPartition));
    }

    @Override
    public void cleanup(IProgressMonitor monitor) throws CleanupFailedException {
        // TODO Auto-generated method stub

    }

    @Override
    public String getName() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public void setBlackboard(VariationOutputBlackBoard blackboard) {
        this.blackboard = blackboard;

    }

}
