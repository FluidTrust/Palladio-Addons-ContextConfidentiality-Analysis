package org.palladiosimulator.pcm.confidentiality.attacker.variation.workflow;

import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;

import org.eclipse.core.runtime.IProgressMonitor;
import org.eclipse.core.runtime.Platform;
import org.eclipse.emf.common.util.URI;
import org.palladiosimulator.dataflow.confidentiality.transformation.workflow.blackboards.KeyValueMDSDBlackboard;
import org.palladiosimulator.pcm.confidentiality.attacker.variation.output.AttackerComponentPathDTO;
import org.palladiosimulator.pcm.confidentiality.attacker.variation.output.VariationOutputBlackBoard;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.config.AttackerAnalysisWorkflowConfig;

import com.google.gson.Gson;

import de.uka.ipd.sdq.workflow.jobs.JobFailedException;
import de.uka.ipd.sdq.workflow.jobs.SequentialBlackboardInteractingJob;
import de.uka.ipd.sdq.workflow.jobs.UserCanceledException;

public class RunMultipleAttackAnalysesJob extends SequentialBlackboardInteractingJob<KeyValueMDSDBlackboard> {
    private VariationWorkflowConfig config;




    public RunMultipleAttackAnalysesJob(VariationWorkflowConfig config) {
        this.config = config;
    }

    @Override
    public void execute(final IProgressMonitor monitor) throws JobFailedException, UserCanceledException {
        var uri = this.config.getVariationModel();
        var rootFolder = uri.trimSegments(2);
        try {
            var scenariosFolderURI = this.config.getScenarioFolder();

            var path = getPath(scenariosFolderURI);

            var listConfigurations = new ArrayList<String>();
            Files.walk(path, 1).filter(content -> content.toFile().isDirectory()).map(Path::getFileName)
                    .map(Path::toString)
                    .forEach(listConfigurations::add);
            listConfigurations.remove(scenariosFolderURI.lastSegment());
            var listPaths = new ArrayList<AttackerComponentPathDTO>();
            for (var scneario : listConfigurations) {
                var configurationURI = scenariosFolderURI.appendSegment(scneario);
                var attackerConfig = new AttackerAnalysisWorkflowConfig();

                attackerConfig.setAllocationModel(getURI(configurationURI, "allocation"));
                attackerConfig.setAttackModel(getURI(configurationURI, "attacker"));
                attackerConfig.setContextModel(getURI(configurationURI, "context"));
                attackerConfig.setModificationModel(getURI(configurationURI, "kamp4attackmodificationmarks"));
                attackerConfig.setRepositoryModel(getURI(configurationURI, "repository"));

                var attackerWorkflow = new FluidAttackerWorkflow(attackerConfig);

                var blackboard = new VariationOutputBlackBoard();
                attackerWorkflow.setBlackboard(blackboard);
                attackerWorkflow.execute(monitor);
                listPaths.add(blackboard.getAttackerPath());

            }
            var gson = new Gson();
            var outputString = gson.toJson(listPaths);
            getBlackboard().put(VariationWorkflowConfig.ID_JSON_ATTACK_PATHS, outputString);


        } catch (URISyntaxException | IOException e) {
            throw new JobFailedException("Problems transforming url", e);
        }

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
