package org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.job;

import java.io.IOException;
import java.nio.file.Files;

import org.apache.log4j.Logger;
import org.eclipse.core.resources.ResourcesPlugin;
import org.eclipse.core.runtime.IProgressMonitor;
import org.eclipse.core.runtime.Path;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.Activator;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.partition.ModificationMarkPartition;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.partition.PartitionConstants;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.config.AttackerAnalysisWorkflowConfig;

import de.uka.ipd.sdq.workflow.jobs.CleanupFailedException;
import de.uka.ipd.sdq.workflow.jobs.IBlackboardInteractingJob;
import de.uka.ipd.sdq.workflow.jobs.JobFailedException;
import de.uka.ipd.sdq.workflow.jobs.UserCanceledException;
import de.uka.ipd.sdq.workflow.mdsd.blackboard.MDSDBlackboard;

public class CreateGraphJob implements IBlackboardInteractingJob<MDSDBlackboard> {

    private final Logger logger = Logger.getLogger(CreateGraphJob.class);

    private MDSDBlackboard blackboard;

    private AttackerAnalysisWorkflowConfig config;

    public CreateGraphJob(AttackerAnalysisWorkflowConfig config) {
        this.config = config;
    }

    @Override
    public void execute(IProgressMonitor monitor) throws JobFailedException, UserCanceledException {

        final var modificationPartition = ((ModificationMarkPartition) this.blackboard
                .getPartition(PartitionConstants.PARTITION_ID_MODIFICATION)).getModificationRepository();

        this.logger.info("Start generating dot graph");
        var file = Activator.getInstance().getGraphCreation().createAttackGraph(modificationPartition)
                .orElseThrow(JobFailedException::new);

        var path = new Path(this.config.getModificationModel().toPlatformString(false));
        var pathString = ResourcesPlugin.getWorkspace().getRoot().getFile(path).getLocation().removeLastSegments(1)
                .toString();

        try {
            var tmpFile = Files.copy(file, java.nio.file.Path.of(pathString, file.getFileName().toString()));
            this.logger.info("File stored at " + tmpFile.toAbsolutePath().toString());
        } catch (IOException e) {
            this.logger.error("Error on file operation", e);
            throw new JobFailedException();
        }

    }



    @Override
    public void cleanup(IProgressMonitor monitor) throws CleanupFailedException {

    }

    @Override
    public String getName() {
        return "Create Graph Job";
    }

    @Override
    public void setBlackboard(MDSDBlackboard blackboard) {
        this.blackboard = blackboard;
    }

}
