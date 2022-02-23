package org.palladiosimulator.pcm.confidentiality.attacker.variation.tests;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.palladiosimulator.pcm.confidentiality.attacker.variation.workflow.VariationWorkflow;
import org.palladiosimulator.pcm.confidentiality.attacker.variation.workflow.VariationWorkflowConfig;
import org.palladiosimulator.pcm.confidentiality.context.analysis.testframework.TestInitializer;

import de.uka.ipd.sdq.workflow.jobs.JobFailedException;
import de.uka.ipd.sdq.workflow.jobs.UserCanceledException;
import tools.mdsd.library.standalone.initialization.StandaloneInitializationException;

class BasicTest {
    @BeforeAll
    static void init() throws StandaloneInitializationException {
        TestInitializer.init();
    }

    @Disabled
    @Test
    void test() throws JobFailedException, UserCanceledException {
        var variationURI = TestInitializer.getModelURI("variations/models/port.uncertaintyvariationmodel");

        var config = new VariationWorkflowConfig();
        config.setVariationModel(variationURI);

        var flow = new VariationWorkflow(config);
//        flow.execute(new NullProgressMonitor());
    }
}
