package org.palladiosimulator.pcm.confidentiality.context.analysis.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.AnalysisResults;
import org.palladiosimulator.pcm.confidentiality.context.analysis.tests.base.BaseTestScenario;
import org.palladiosimulator.pcm.confidentiality.context.model.HierarchicalContext;
import org.palladiosimulator.pcm.confidentiality.context.model.IncludeDirection;
import org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.api.PCMBlackBoard;
import org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.provider.ScenarioAnalysisImpl;

class ScenarioTests extends BaseTestScenario {
    @Test
    @DisplayName("01_no_context_usage_model")
    void noContext() {
        final var blackBoard = new PCMBlackBoard(this.assembly, this.repo, this.usage);
        final var analysis = new ScenarioAnalysisImpl();
        // clear existing policies
        this.context.getSetContainer().stream().flatMap(e -> e.getPolicies().stream())
                .forEach(e -> e.getContexts().clear());

        final var output = analysis.runScenarioAnalysis(blackBoard, this.context);
        assertNotNull(output.getScenariooutput());
        for (final var scenario : output.getScenariooutput()) {
            assertFalse(scenario.isResult());
        }
    }

    @Test
    @DisplayName("02_context")
    void allPositive() {
        final var blackBoard = new PCMBlackBoard(this.assembly, this.repo, this.usage);
        final var analysis = new ScenarioAnalysisImpl();
        final var output = analysis.runScenarioAnalysis(blackBoard, this.context);
        this.assertAllPositive(output);
    }

    @Test
    @DisplayName("03_wrong_context_type")
    void wrongType() {
        final var blackBoard = new PCMBlackBoard(this.assembly, this.repo, this.usage);
        final var analysis = new ScenarioAnalysisImpl();

        final var contextAttribute = this.createSingleContext("Customer");
        this.context.getContextContainer().get(0).getContext().add(contextAttribute);
        this.clearContextSetByName("UsageGetFlight");// modify requestor contexts --> multiple fails
        // possible
        this.getContextSetByName("UsageGetFlight").getContexts().add(contextAttribute);

        final var output = analysis.runScenarioAnalysis(blackBoard, this.context);
        assertNotNull(output.getScenariooutput());

        assertTrue(this.getScenarioResultByName(output, "AdministrationCreditCardData"));

        final var listOutput = this.getScenariosByName(output, "defaultUsageScenario");
        assertEquals(3, listOutput.size());
        for (final var scenario : listOutput) {
            assertFalse(scenario.isResult());
        }

    }

    @Test
    @DisplayName("04_hierachical_top_down")
    void hierachicalTopDown() {
        final var blackBoard = new PCMBlackBoard(this.assembly, this.repo, this.usage);
        final var analysis = new ScenarioAnalysisImpl();

        this.clearContextSetByName("UsageGetFlight");
        this.getContextSetByName("UsageGetFlight").getContexts().add(this.getContextAttributeByName("root"));

        final var output = analysis.runScenarioAnalysis(blackBoard, this.context);
        this.assertAllPositive(output);
    }

    @Test
    @DisplayName("05_h_tp_error")
    void hierachicalTopDownError() {
        final var blackBoard = new PCMBlackBoard(this.assembly, this.repo, this.usage);
        final var analysis = new ScenarioAnalysisImpl();

        this.clearContextSetByName("AccessOperationGetFlightOffers"); // modify access policies -->
                                                                      // only
        // one fail possible
        this.getContextSetByName("AccessOperationGetFlightOffers").getContexts()
                .add(this.getContextAttributeByName("root"));

        final var output = analysis.runScenarioAnalysis(blackBoard, this.context);
        assertNotNull(output.getScenariooutput());

        assertTrue(this.getScenarioResultByName(output, "AdministrationCreditCardData"));
        final var listOutput = this.getScenariosByName(output, "defaultUsageScenario");
        assertEquals(1, listOutput.size());
        for (final var scenario : listOutput) {
            assertFalse(scenario.isResult());
        }
    }

    @Test
    @DisplayName("06_h_tp_2_layers")
    void hierachicalTopDown2() {
        final var blackBoard = new PCMBlackBoard(this.assembly, this.repo, this.usage);
        final var analysis = new ScenarioAnalysisImpl();

        this.clearContextSetByName("UsageGetFlight");
        this.getContextSetByName("UsageGetFlight").getContexts().add(this.getContextAttributeByName("root"));

        // insert middlde element to root
        final var contextRoot = this.getContextAttributeByName("root");
        final var middleContext = this.createHierarchicalContext("Middle");
        middleContext.setDirection(IncludeDirection.TOP_DOWN);
        middleContext.getIncluding().add(this.getContextAttributeByName("Customer"));
        middleContext.setContexttype(contextRoot.getContexttype());
        this.context.getContextContainer().get(0).getContext().add(middleContext);
        ((HierarchicalContext) contextRoot).getIncluding().clear();
        ((HierarchicalContext) contextRoot).getIncluding().add(middleContext);

        final var output = analysis.runScenarioAnalysis(blackBoard, this.context);
        this.assertAllPositive(output);
    }

    private void assertAllPositive(final AnalysisResults output) {
        assertNotNull(output.getScenariooutput());

        for (final var scenario : output.getScenariooutput()) {
            assertTrue(scenario.isResult());
        }
    }

    @Test
    @DisplayName("07_h_tp_2_l_error")
    void hierachicalTopDown2Error() {
        final var blackBoard = new PCMBlackBoard(this.assembly, this.repo, this.usage);
        final var analysis = new ScenarioAnalysisImpl();

        this.clearContextSetByName("AccessOperationGetFlightOffers"); // modify access policies -->
                                                                      // only
        // one fail possible
        this.getContextSetByName("AccessOperationGetFlightOffers").getContexts()
                .add(this.getContextAttributeByName("root"));

        // insert middlde element to root
        final var contextRoot = this.getContextAttributeByName("root");
        final var middleContext = this.createHierarchicalContext("Middle");
        middleContext.setDirection(IncludeDirection.TOP_DOWN);
        middleContext.getIncluding().add(this.getContextAttributeByName("Customer"));
        middleContext.setContexttype(contextRoot.getContexttype());
        this.context.getContextContainer().get(0).getContext().add(middleContext);
        ((HierarchicalContext) contextRoot).getIncluding().clear();
        ((HierarchicalContext) contextRoot).getIncluding().add(middleContext);

        final var output = analysis.runScenarioAnalysis(blackBoard, this.context);
        assertNotNull(output.getScenariooutput());

        assertTrue(this.getScenarioResultByName(output, "AdministrationCreditCardData"));
        final var listOutput = this.getScenariosByName(output, "defaultUsageScenario");
        assertEquals(1, listOutput.size());
        for (final var scenario : listOutput) {
            assertFalse(scenario.isResult());
        }
    }

    @Test
    @DisplayName("08_h_tp_2_children")
    void hierachicalTopDownC() {
        final var blackBoard = new PCMBlackBoard(this.assembly, this.repo, this.usage);
        final var analysis = new ScenarioAnalysisImpl();

        this.clearContextSetByName("UsageGetFlight");
        this.getContextSetByName("UsageGetFlight").getContexts().add(this.getContextAttributeByName("root"));

        // insert middlde element to root
        final var contextRoot = this.getContextAttributeByName("root");
        final var child2 = this.createHierarchicalContext("Child");
        child2.setDirection(IncludeDirection.TOP_DOWN);
        child2.setContexttype(contextRoot.getContexttype());
        this.context.getContextContainer().get(0).getContext().add(child2);
        ((HierarchicalContext) contextRoot).getIncluding().add(child2);

        final var output = analysis.runScenarioAnalysis(blackBoard, this.context);
        this.assertAllPositive(output);
    }

    @Test
    @DisplayName("09_h_tp_2_c_error")
    void hierachicalTopDownCError() {
        final var blackBoard = new PCMBlackBoard(this.assembly, this.repo, this.usage);
        final var analysis = new ScenarioAnalysisImpl();

        this.clearContextSetByName("UsageGetFlight");

        // insert middlde element to root
        final var contextRoot = this.getContextAttributeByName("root");
        final var child2 = this.createHierarchicalContext("Child");
        child2.setDirection(IncludeDirection.TOP_DOWN);
        child2.setContexttype(contextRoot.getContexttype());
        this.context.getContextContainer().get(0).getContext().add(child2);
        ((HierarchicalContext) contextRoot).getIncluding().add(child2);
        this.getContextSetByName("UsageGetFlight").getContexts().add(child2);

        final var output = analysis.runScenarioAnalysis(blackBoard, this.context);

        assertTrue(this.getScenarioResultByName(output, "AdministrationCreditCardData"));
        final var listOutput = this.getScenariosByName(output, "defaultUsageScenario");
        assertEquals(3, listOutput.size());
        for (final var scenario : listOutput) {
            assertFalse(scenario.isResult());
        }
    }

    @Test
    @DisplayName("10_h_bottom_up")
    void hierachicalBottomUp() {
        final var blackBoard = new PCMBlackBoard(this.assembly, this.repo, this.usage);
        final var analysis = new ScenarioAnalysisImpl();

        // create Bottom Up Value HomeCity
        final var homeCity = this.createHierarchicalContext("Home-City");
        homeCity.setDirection(IncludeDirection.BOTTOM_UP);
        homeCity.setContexttype(this.getContextAttributeByName("Home").getContexttype());
        homeCity.getIncluding().add(this.getContextAttributeByName("Home"));

        this.clearContextSetByName("AccessOperationSetDeclassified");
        this.getContextSetByName("AccessOperationSetDeclassified").getContexts().add(homeCity);
        this.getContextSetByName("AccessOperationSetDeclassified").getContexts()
                .add(this.getContextAttributeByName("Customer"));

        final var output = analysis.runScenarioAnalysis(blackBoard, this.context);
        this.assertAllPositive(output);
    }

    @Test
    @DisplayName("11_h_b_u_error")
    void hierachicalBottomUpError() {
        final var blackBoard = new PCMBlackBoard(this.assembly, this.repo, this.usage);
        final var analysis = new ScenarioAnalysisImpl();

        // create Bottom Up Value HomeCity
        final var homeCity = this.createHierarchicalContext("Home-City");
        homeCity.setDirection(IncludeDirection.BOTTOM_UP);
        homeCity.setContexttype(this.getContextAttributeByName("Home").getContexttype());
        homeCity.getIncluding().add(this.getContextAttributeByName("Home"));

        this.clearContextSetByName("UsageReleaseCCD");
        this.getContextSetByName("UsageReleaseCCD").getContexts().add(homeCity);
        this.getContextSetByName("UsageReleaseCCD").getContexts().add(this.getContextAttributeByName("Customer"));

        final var output = analysis.runScenarioAnalysis(blackBoard, this.context);

        assertTrue(this.getScenarioResultByName(output, "AdministrationCreditCardData"));
        final var listOutput = this.getScenariosByName(output, "defaultUsageScenario");
        assertEquals(1, listOutput.size());
        for (final var scenario : listOutput) {
            assertFalse(scenario.isResult());
        }
    }

    @Test
    @DisplayName("12_h_b_u_2_layers")
    void hierachicalBottomUp2() {
        final var blackBoard = new PCMBlackBoard(this.assembly, this.repo, this.usage);
        final var analysis = new ScenarioAnalysisImpl();

        // create Bottom Up Value HomeState
        final var homeCity = this.createHierarchicalContext("Home-City");
        homeCity.setDirection(IncludeDirection.BOTTOM_UP);
        homeCity.setContexttype(this.getContextAttributeByName("Home").getContexttype());
        homeCity.getIncluding().add(this.getContextAttributeByName("Home"));

        final var homeState = this.createHierarchicalContext("Home-State");
        homeState.setDirection(IncludeDirection.BOTTOM_UP);
        homeState.setContexttype(homeCity.getContexttype());
        homeState.getIncluding().add(homeCity);

        this.clearContextSetByName("AccessOperationSetDeclassified");
        this.getContextSetByName("AccessOperationSetDeclassified").getContexts().add(homeState);
        this.getContextSetByName("AccessOperationSetDeclassified").getContexts()
                .add(this.getContextAttributeByName("Customer"));

        final var output = analysis.runScenarioAnalysis(blackBoard, this.context);
        this.assertAllPositive(output);
    }

    @Test
    @DisplayName("13_h_b_u_2_l_error")
    void hierachicalBottomUp2E() {
        final var blackBoard = new PCMBlackBoard(this.assembly, this.repo, this.usage);
        final var analysis = new ScenarioAnalysisImpl();

        // create Bottom Up Value HomeState
        final var homeCity = this.createHierarchicalContext("Home-City");
        homeCity.setDirection(IncludeDirection.BOTTOM_UP);
        homeCity.setContexttype(this.getContextAttributeByName("Home").getContexttype());
        homeCity.getIncluding().add(this.getContextAttributeByName("Home"));

        final var homeState = this.createHierarchicalContext("Home-State");
        homeState.setDirection(IncludeDirection.BOTTOM_UP);
        homeState.setContexttype(homeCity.getContexttype());
        homeState.getIncluding().add(homeCity);

        this.clearContextSetByName("UsageReleaseCCD");
        this.getContextSetByName("UsageReleaseCCD").getContexts().add(homeState);
        this.getContextSetByName("UsageReleaseCCD").getContexts().add(this.getContextAttributeByName("Customer"));

        final var output = analysis.runScenarioAnalysis(blackBoard, this.context);

        assertTrue(this.getScenarioResultByName(output, "AdministrationCreditCardData"));
        final var listOutput = this.getScenariosByName(output, "defaultUsageScenario");
        assertEquals(1, listOutput.size());
        for (final var scenario : listOutput) {
            assertFalse(scenario.isResult());
        }
    }

    @Test
    @DisplayName("14_h_b_u_2_children")
    void hierachicalBottomUp2child() {
        final var blackBoard = new PCMBlackBoard(this.assembly, this.repo, this.usage);
        final var analysis = new ScenarioAnalysisImpl();

        // create Bottom Up Value HomeState
        final var homeCity = this.createHierarchicalContext("Home-City");
        homeCity.setDirection(IncludeDirection.BOTTOM_UP);
        homeCity.setContexttype(this.getContextAttributeByName("Home").getContexttype());
        homeCity.getIncluding().add(this.getContextAttributeByName("Home"));

        final var friend = this.createSingleContext("FriendsHome");
        friend.setContexttype(homeCity.getContexttype());

        homeCity.getIncluding().add(friend);

        this.clearContextSetByName("AccessOperationSetDeclassified");
        this.getContextSetByName("AccessOperationSetDeclassified").getContexts().add(homeCity);
        this.getContextSetByName("AccessOperationSetDeclassified").getContexts()
                .add(this.getContextAttributeByName("Customer"));

        final var output = analysis.runScenarioAnalysis(blackBoard, this.context);
        this.assertAllPositive(output);
    }

    @Test
    @DisplayName("15_h_b_u_2_c_error")
    void hierachicalBottomUp2childError() {
        final var blackBoard = new PCMBlackBoard(this.assembly, this.repo, this.usage);
        final var analysis = new ScenarioAnalysisImpl();

        // create Bottom Up Value HomeState
        final var homeCity = this.createHierarchicalContext("Home-City");
        homeCity.setDirection(IncludeDirection.BOTTOM_UP);
        homeCity.setContexttype(this.getContextAttributeByName("Home").getContexttype());
        homeCity.getIncluding().add(this.getContextAttributeByName("Home"));

        final var friend = this.createSingleContext("FriendsHome");
        friend.setContexttype(homeCity.getContexttype());

        homeCity.getIncluding().add(friend);

        this.clearContextSetByName("UsageReleaseCCD");
        this.getContextSetByName("UsageReleaseCCD").getContexts().add(homeCity);
        this.getContextSetByName("UsageReleaseCCD").getContexts().add(this.getContextAttributeByName("Customer"));

        final var output = analysis.runScenarioAnalysis(blackBoard, this.context);

        assertTrue(this.getScenarioResultByName(output, "AdministrationCreditCardData"));
        final var listOutput = this.getScenariosByName(output, "defaultUsageScenario");
        assertEquals(1, listOutput.size());
        for (final var scenario : listOutput) {
            assertFalse(scenario.isResult());
        }
    }

    @Test
    @DisplayName("16_related_context_set")
    void relatedContextSet() {
        final var blackBoard = new PCMBlackBoard(this.assembly, this.repo, this.usage);
        final var analysis = new ScenarioAnalysisImpl();

        final var related = this.createRelatedContext("Related");
        related.setContextset(this.getContextSetByName("UsageReleaseCCD"));
        this.context.getContextContainer().get(0).getContext().add(related);

        this.getContextSetByName("AccessOperationSetDeclassified").getContexts().add(related);
        this.getContextSetByName("UsageDeclassifyCCD").getContexts().add(related);

        final var output = analysis.runScenarioAnalysis(blackBoard, this.context);
        this.assertAllPositive(output);
    }

    @Test
    @DisplayName("17_r_c_s_error")
    void relatedContextSetError() {
        final var blackBoard = new PCMBlackBoard(this.assembly, this.repo, this.usage);
        final var analysis = new ScenarioAnalysisImpl();

        final var related = this.createRelatedContext("Related");
        related.setContextset(this.getContextSetByName("UsageReleaseCCD"));
        this.context.getContextContainer().get(0).getContext().add(related);

        this.getContextSetByName("AccessOperationSetDeclassified").getContexts().add(related);

        final var output = analysis.runScenarioAnalysis(blackBoard, this.context);

        assertTrue(this.getScenarioResultByName(output, "AdministrationCreditCardData"));
        final var listOutput = this.getScenariosByName(output, "defaultUsageScenario");
        assertEquals(1, listOutput.size());
        for (final var scenario : listOutput) {
            assertFalse(scenario.isResult());
        }
    }

    @Test
    @DisplayName("18_missusage") // no authentification from user only home
    void misusage() {
        final var blackBoard = new PCMBlackBoard(this.assembly, this.repo, this.usage);
        final var analysis = new ScenarioAnalysisImpl();

        this.getSpecificationByName("UsageAdministrationCreditCardData").setMissageUse(true);
        this.clearContextSetByName("UsageAdministrationCreditCardData");
        this.getContextSetByName("UsageAdministrationCreditCardData").getContexts()
                .add(this.getContextAttributeByName("Home"));

        final var output = analysis.runScenarioAnalysis(blackBoard, this.context);
        this.assertAllPositive(output);
    }

    @Test
    @DisplayName("19_m_error")
    void misusageError() {
        final var blackBoard = new PCMBlackBoard(this.assembly, this.repo, this.usage);
        final var analysis = new ScenarioAnalysisImpl();

        this.getSpecificationByName("UsageAdministrationCreditCardData").setMissageUse(true);

        final var output = analysis.runScenarioAnalysis(blackBoard, this.context);

        assertTrue(this.getScenarioByName(output, "defaultUsageScenario").isResult());
        assertFalse(this.getScenarioResultByName(output, "AdministrationCreditCardData"));
    }

    @Test
    @DisplayName("20_more_context_sets")
    void multipleSets() {
        final var blackBoard = new PCMBlackBoard(this.assembly, this.repo, this.usage);
        final var analysis = new ScenarioAnalysisImpl();

        final var homeCity = this.createHierarchicalContext("Home-City");
        homeCity.setDirection(IncludeDirection.BOTTOM_UP);
        homeCity.setContexttype(this.getContextAttributeByName("Home").getContexttype());
        homeCity.getIncluding().add(this.getContextAttributeByName("Home"));
        this.context.getContextContainer().get(0).getContext().add(homeCity);

        this.getContextSetByName("UsageAdministrationCreditCardData").getContexts()
                .add(this.getContextAttributeByName("root"));
        this.getContextSetByName("UsageAdministrationCreditCardData").getContexts().add(homeCity);

        final var output = analysis.runScenarioAnalysis(blackBoard, this.context);

        assertTrue(this.getScenarioByName(output, "defaultUsageScenario").isResult());
        assertTrue(this.getScenarioResultByName(output, "AdministrationCreditCardData"));
    }

    @Test
    @DisplayName("21_mismatch")
    void mismatch() {
        final var blackBoard = new PCMBlackBoard(this.assembly, this.repo, this.usage);
        final var analysis = new ScenarioAnalysisImpl();

        this.getContextSetByName("AccessOperationGetFlightOffersTravelAgencyAirline").getContexts()
                .add(this.getContextAttributeByName("Home"));

        final var output = analysis.runScenarioAnalysis(blackBoard, this.context);

        assertFalse(this.getScenarioByName(output, "defaultUsageScenario").isResult());
        assertTrue(this.getScenarioResultByName(output, "AdministrationCreditCardData"));
    }

}
