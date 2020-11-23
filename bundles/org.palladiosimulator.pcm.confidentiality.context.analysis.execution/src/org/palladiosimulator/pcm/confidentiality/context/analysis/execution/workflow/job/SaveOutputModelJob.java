package org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.job;

import org.eclipse.core.runtime.IProgressMonitor;
import org.eclipse.emf.common.util.URI;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.config.ContextAnalysisWorkflowConfig;
import static org.palladiosimulator.pcm.confidentiality.context.analysis.execution.partition.PartitionConstants.PARTITION_ID_OUTPUT;

import java.io.IOException;
import java.util.Collections;

import de.uka.ipd.sdq.workflow.jobs.CleanupFailedException;
import de.uka.ipd.sdq.workflow.jobs.IBlackboardInteractingJob;
import de.uka.ipd.sdq.workflow.jobs.JobFailedException;
import de.uka.ipd.sdq.workflow.jobs.UserCanceledException;
import de.uka.ipd.sdq.workflow.mdsd.blackboard.MDSDBlackboard;

public class SaveOutputModelJob implements IBlackboardInteractingJob<MDSDBlackboard> {

    protected MDSDBlackboard blackboard;
    protected final ContextAnalysisWorkflowConfig configuration;

    public SaveOutputModelJob(final ContextAnalysisWorkflowConfig configuration) {
        this.configuration = configuration;
    }

    @Override
    public void execute(IProgressMonitor monitor) throws JobFailedException, UserCanceledException {
        var partitionOutput = blackboard.getPartition(PARTITION_ID_OUTPUT);

        var test = configuration.getAllocationModel();
        var segments = test.segments();
        segments[test.segmentCount()-1] = "my.output";
        var testUri = URI.createPlatformResourceURI(segments[1] + "/" + segments[2], true);
        
        var resource = partitionOutput.getResourceSet().createResource(testUri);
        try {
           resource.getContents().add(partitionOutput.getResourceSet().getResources().get(0).getContents().get(0));
            resource.save(Collections.EMPTY_MAP);
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
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
    public void setBlackboard(MDSDBlackboard blackboard) {
        this.blackboard = blackboard;
    }

}
