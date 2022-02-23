package org.palladiosimulator.pcm.confidentiality.attacker.variation.workflow;

import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.eclipse.core.runtime.Platform;
import org.eclipse.emf.common.util.URI;
import org.modelversioning.emfprofile.registry.IProfileRegistry;
import org.palladiosimulator.dataflow.confidentiality.transformation.workflow.blackboards.KeyValueMDSDBlackboard;
import org.palladiosimulator.pcm.uncertainty.variation.UncertaintyVariationModel.gen.pcm.workflow.UncertaintyWorkflowJob;

import de.uka.ipd.sdq.workflow.jobs.SequentialBlackboardInteractingJob;
import tools.mdsd.library.standalone.initialization.StandaloneInitializationException;
import tools.mdsd.library.standalone.initialization.emfprofiles.EMFProfileInitializationTask;

public class VariationWorkflow extends SequentialBlackboardInteractingJob<KeyValueMDSDBlackboard> {
    public VariationWorkflow(VariationWorkflowConfig config) {

        IProfileRegistry.eINSTANCE.getClass();

        try {
            new EMFProfileInitializationTask("org.palladiosimulator.dataflow.confidentiality.pcm.model.profile",
                    "profile.emfprofile_diagram").initilizationWithoutPlatform();
        } catch (StandaloneInitializationException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        this.add(new UncertaintyWorkflowJob(config.getVariationModel()));
        this.add(new RunCriticalityAnalysis(config));
        this.add(new RunMultipleAttackAnalysesJob(config));



        try {
            this.add(new SaveStringToDiskJob(getPath(config.getScenarioFolder().appendSegment("paths.json")).toFile(),
                    VariationWorkflowConfig.ID_JSON_ATTACK_PATHS));
            this.add(new SaveStringToDiskJob(
                    getPath(config.getScenarioFolder().appendSegment("critical_data.json")).toFile(),
                    VariationWorkflowConfig.ID_JSON_DATA));

        } catch (URISyntaxException | IOException e) {
            throw new IllegalStateException("Error while converting URIs for output", e);
        }

    }

    private Path getPath(final URI uri) throws URISyntaxException, IOException {
        var url = new URL(uri.toString());
        return Paths.get(Platform.asLocalURL(url).toURI().getSchemeSpecificPart());
    }

}
