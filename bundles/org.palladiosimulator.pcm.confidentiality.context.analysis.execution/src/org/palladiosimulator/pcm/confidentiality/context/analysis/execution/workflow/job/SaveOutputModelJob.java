package org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.job;

import static org.palladiosimulator.pcm.confidentiality.context.analysis.execution.partition.PartitionConstants.PARTITION_ID_OUTPUT;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;

import org.eclipse.core.runtime.IProgressMonitor;
import org.eclipse.emf.common.util.URI;
import org.eclipse.emf.ecore.xmi.XMLResource;
import org.eclipse.emf.ecore.xmi.impl.URIHandlerImpl;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.config.ContextAnalysisWorkflowConfig;

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
    public void execute(final IProgressMonitor monitor) throws JobFailedException, UserCanceledException {
        final var partitionOutput = this.blackboard.getPartition(PARTITION_ID_OUTPUT);

        final var test = this.configuration.getContextModel();


        final var segments = test.segments();
        segments[test.segmentCount() - 1] = "my" + System.currentTimeMillis();

        var outputString = new StringBuilder();

        for (var i = 1; i < segments.length-1; i++) {
            outputString.append(segments[i]);
            outputString.append(File.separator);
        }
        outputString.append("my" + System.currentTimeMillis() + ".outputmodel");


        final var testUri = URI.createPlatformResourceURI(outputString.toString(), true);
        final var resource = partitionOutput.getResourceSet().createResource(testUri);
        try {
            resource.getContents().add(partitionOutput.getResourceSet().getResources().get(0).getContents().get(0));
            var saveMap = new HashMap<>();
            saveMap.put(XMLResource.OPTION_USE_ENCODED_ATTRIBUTE_STYLE, Boolean.TRUE);
            saveMap.put(XMLResource.OPTION_URI_HANDLER, new URIHandlerImpl.AbsoluteCrossBundleAware());
            resource.save(saveMap);
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
