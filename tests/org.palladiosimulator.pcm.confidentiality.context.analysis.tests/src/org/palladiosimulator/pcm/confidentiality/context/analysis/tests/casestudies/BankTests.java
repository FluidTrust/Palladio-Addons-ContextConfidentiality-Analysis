package org.palladiosimulator.pcm.confidentiality.context.analysis.tests.casestudies;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.palladiosimulator.pcm.confidentiality.context.analysis.tests.base.casestudies.BankBaseTest;
import org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.api.Configuration;
import org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.api.PCMBlackBoard;
import org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.provider.ScenarioAnalysisSystemImpl;

public class BankTests extends BankBaseTest {

    @BeforeEach
    void initLocal() {
        this.blackBoard = new PCMBlackBoard(this.assembly, this.repo, this.usage);
        this.analysis = new ScenarioAnalysisSystemImpl();
        this.configuration = new Configuration(false, this.eval);
    }

    @Test
    void positiveCase() {
        this.generateXML();
        final var output = this.analysis.runScenarioAnalysis(this.blackBoard, this.context, this.configuration);
        this.assertAllPositive(output);
    }

}
