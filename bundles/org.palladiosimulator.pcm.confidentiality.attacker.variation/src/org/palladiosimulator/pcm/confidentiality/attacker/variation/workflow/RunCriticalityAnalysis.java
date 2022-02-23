package org.palladiosimulator.pcm.confidentiality.attacker.variation.workflow;

import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Objects;

import org.eclipse.core.runtime.IProgressMonitor;
import org.eclipse.core.runtime.Platform;
import org.eclipse.emf.common.util.URI;
import org.palladiosimulator.dataflow.confidentiality.transformation.workflow.blackboards.KeyValueMDSDBlackboard;
import org.palladiosimulator.dataflow.confidentiality.transformation.workflow.jobs.LoadModelJob;

import com.google.gson.Gson;

import de.uka.ipd.sdq.workflow.jobs.AbstractBlackboardInteractingJob;
import de.uka.ipd.sdq.workflow.jobs.CleanupFailedException;
import de.uka.ipd.sdq.workflow.jobs.JobFailedException;
import de.uka.ipd.sdq.workflow.jobs.SequentialBlackboardInteractingJob;
import de.uka.ipd.sdq.workflow.jobs.UserCanceledException;
import de.uka.ipd.sdq.workflow.mdsd.blackboard.ModelLocation;
import edu.kit.kastel.dsis.fluidtrust.datacharacteristic.analysis.jobs.PropagateCharacteristicJob;

public class RunCriticalityAnalysis extends AbstractBlackboardInteractingJob<KeyValueMDSDBlackboard> {

    protected static final String PCM_MODEL_PARTITION = "pcmModels";

    private VariationWorkflowConfig config;

    public RunCriticalityAnalysis(VariationWorkflowConfig config) {
        Objects.requireNonNull(config);
        this.config = config;
    }

    @Override
    public void execute(IProgressMonitor monitor) throws JobFailedException, UserCanceledException {

        var folderURI = this.config.getModelFolder();
        var job = new SequentialBlackboardInteractingJob<KeyValueMDSDBlackboard>();
        job.setBlackboard(new KeyValueMDSDBlackboard());
        try {
            var usageModelLocation = new ModelLocation(PCM_MODEL_PARTITION, getURI(folderURI, "usagemodel"));
            var allocationLocation = new ModelLocation(PCM_MODEL_PARTITION, getURI(folderURI, "allocation"));
            var loadUsageModelJob = new LoadModelJob<KeyValueMDSDBlackboard>(
                    Arrays.asList(usageModelLocation, allocationLocation));
            job.add(loadUsageModelJob);
            var runAnalysisJob = new PropagateCharacteristicJob(usageModelLocation, allocationLocation, "test");
            job.add(runAnalysisJob);
            job.execute(monitor);
            var data = job.getBlackboard().get("test");
            var gson = new Gson();
            var outputString = gson.toJson(data.get());
            getBlackboard().put(VariationWorkflowConfig.ID_JSON_DATA, outputString);

        } catch (IOException | URISyntaxException e) {
            throw new JobFailedException("Failure finding models", e);
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

    private URI getURI(URI folder, String modelFileExtension) throws IOException, URISyntaxException {
        var path = getPath(folder);
        var modelFile = Files.walk(path).filter(file -> file.toString().endsWith(modelFileExtension)).findAny().get()
                .getFileName().toString();
        return folder.appendSegment(modelFile);
    }

    private Path getPath(final URI uri) throws URISyntaxException, IOException {
        var url = new URL(uri.toString());
        return Paths.get(Platform.asLocalURL(url).toURI().getSchemeSpecificPart());
    }
}
