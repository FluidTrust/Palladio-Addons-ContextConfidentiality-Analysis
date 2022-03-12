package org.palladiosimulator.pcm.confidentiality.attacker.variation.tests;

import org.eclipse.core.runtime.NullProgressMonitor;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.palladiosimulator.pcm.confidentiality.attacker.variation.workflow.RunCriticalityAnalysis;
import org.palladiosimulator.pcm.confidentiality.attacker.variation.workflow.VariationWorkflowConfig;
import org.palladiosimulator.pcm.confidentiality.context.analysis.testframework.TestInitializer;

import de.uka.ipd.sdq.workflow.jobs.JobFailedException;
import de.uka.ipd.sdq.workflow.jobs.UserCanceledException;
import tools.mdsd.library.standalone.initialization.StandaloneInitializationException;
import tools.mdsd.library.standalone.initialization.emfprofiles.EMFProfileInitializationTask;

class BasicTest {
    @BeforeAll
    static void init() throws StandaloneInitializationException {
        TestInitializer.init();
        try {
            new EMFProfileInitializationTask("org.palladiosimulator.dataflow.confidentiality.pcm.model.profile",
                    "profile.emfprofile_diagram").initilizationWithoutPlatform();
        } catch (final StandaloneInitializationException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    @Disabled
    @Test
    void test() throws JobFailedException, UserCanceledException {
        final var variationURI = TestInitializer.getModelURI("variations/models/port.uncertaintyvariationmodel");


        final var config = new VariationWorkflowConfig();
        config.setVariationModel(variationURI);

        final var flow = new RunCriticalityAnalysis(config);
        flow.execute(new NullProgressMonitor());

    }
}
