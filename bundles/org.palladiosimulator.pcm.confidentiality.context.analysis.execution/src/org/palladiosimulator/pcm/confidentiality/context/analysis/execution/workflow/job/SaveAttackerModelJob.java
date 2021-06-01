package org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.job;

import static org.palladiosimulator.pcm.confidentiality.context.analysis.execution.partition.PartitionConstants.PARTITION_ID_ATTACK;

import java.io.IOException;
import java.util.Collections;

import org.eclipse.core.runtime.IProgressMonitor;
import org.eclipse.emf.common.util.URI;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.config.AttackerAnalysisWorkflowConfig;

import de.uka.ipd.sdq.workflow.jobs.CleanupFailedException;
import de.uka.ipd.sdq.workflow.jobs.IBlackboardInteractingJob;
import de.uka.ipd.sdq.workflow.jobs.JobFailedException;
import de.uka.ipd.sdq.workflow.jobs.UserCanceledException;
import de.uka.ipd.sdq.workflow.mdsd.blackboard.MDSDBlackboard;

public class SaveAttackerModelJob implements IBlackboardInteractingJob<MDSDBlackboard> {

    protected MDSDBlackboard blackboard;
    protected final AttackerAnalysisWorkflowConfig configuration;

    public SaveAttackerModelJob(final AttackerAnalysisWorkflowConfig configuration) {
        this.configuration = configuration;
    }

    @Override
    public void execute(final IProgressMonitor monitor) throws JobFailedException, UserCanceledException {
        final var partitionOutput = this.blackboard.getPartition(PARTITION_ID_ATTACK);

        final var test = this.configuration.getAttackModel();
        final var segments = test.segments();
        segments[test.segmentCount() - 1] = "attacker.output.attacker";
        final var testUri = URI.createPlatformResourceURI(segments[1] + "/" + segments[2], true);

        final var resource = partitionOutput.getResourceSet().createResource(testUri);
        try {
            resource.getContents().add(partitionOutput.getResourceSet().getResources().get(0).getContents().get(0));
            resource.save(Collections.EMPTY_MAP);
        } catch (final IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    @Override
    public void cleanup(final IProgressMonitor monitor) throws CleanupFailedException {
        // TODO Auto-generated method stub

    }

    @Override
    public String getName() {
        // TODO Auto-generated method stub
        return "Save Scenario Analysis Job";
    }

    @Override
    public void setBlackboard(final MDSDBlackboard blackboard) {
        this.blackboard = blackboard;
    }

}
