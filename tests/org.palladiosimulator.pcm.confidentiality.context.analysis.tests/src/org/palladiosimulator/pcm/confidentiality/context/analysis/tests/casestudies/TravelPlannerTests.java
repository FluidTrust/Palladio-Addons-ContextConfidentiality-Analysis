package org.palladiosimulator.pcm.confidentiality.context.analysis.tests.casestudies;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.palladiosimulator.pcm.confidentiality.context.analysis.tests.base.casestudies.TravelPlannerBaseTest;
import org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.api.Configuration;
import org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.api.PCMBlackBoard;
import org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.provider.ScenarioAnalysisSystemImpl;

class TravelPlannerTests extends TravelPlannerBaseTest {

    @BeforeEach
    void initLocal() {
        this.blackBoard = new PCMBlackBoard(this.assembly, this.repo, this.usage);
        this.analysis = new ScenarioAnalysisSystemImpl();
        this.configuration = new Configuration(false, this.eval);
    }

    @Test
    @DisplayName("01_no_context_usage_model")
    void noContext() {
        // clear existing policies
        this.context.getPolicyset()
            .getPolicy()
            .clear();
        this.context.getPolicyset()
            .getPolicyset()
            .clear();
        this.blackBoard.getUsageModel()
            .getUsageScenario_UsageModel()
            .remove(0);

        this.generateXML();
        final var analysis = new ScenarioAnalysisSystemImpl();
        final var output = analysis.runScenarioAnalysis(this.blackBoard, this.context, this.configuration);
        assertNotNull(output.getScenariooutput());

        output.getScenariooutput()
            .stream()
            .filter(e -> e.getScenario()
                .getEntityName()
                .contains("Misusage"))
            .forEach(e -> assertTrue(e.isPassed()));
        output.getScenariooutput()
            .stream()
            .filter(e -> !e.getScenario()
                .getEntityName()
                .contains("Misusage"))
            .forEach(e -> assertFalse(e.isPassed()));
    }

    @Test
    @DisplayName("02_context")
    void allPositive() {
        this.generateXML();
        final var output = this.analysis.runScenarioAnalysis(this.blackBoard, this.context, this.configuration);
        this.assertAllPositive(output);
    }

    // @Test
    // @DisplayName("03_wrong_context_type")
    // void wrongType() {
    //
    // final var contextAttribute = createSingleContext("Customer");
    // this.context.getContextContainer().get(0).getContext().add(contextAttribute);
    // clearContextSetByName("UsageGetFlight");// modify requestor contexts --> multiple fails
    // // possible
    // getContextSetByName("UsageGetFlight").getContexts().add(contextAttribute);
    //
    // final var output = this.analysis.runScenarioAnalysis(this.blackBoard, this.context,
    // this.configuration);
    // assertNotNull(output.getScenariooutput());
    //
    // assertTrue(getScenarioResultByName(output, "AdministrationCreditCardData"));
    //
    // final var listOutput = getScenariosByName(output, "defaultUsageScenario");
    // assertEquals(3, listOutput.size());
    // for (final var scenario : listOutput) {
    // assertFalse(scenario.isResult());
    // }
    //
    // }
    //
    // @Test
    // @DisplayName("04_hierachical_top_down")
    // void hierachicalTopDown() {
    //
    // clearContextSetByName("UsageGetFlight");
    // getContextSetByName("UsageGetFlight").getContexts().add(getContextAttributeByName("root"));
    //
    // final var output = this.analysis.runScenarioAnalysis(this.blackBoard, this.context,
    // this.configuration);
    // assertAllPositive(output);
    // }
    //
    // @Test
    // @DisplayName("05_h_tp_error")
    // void hierachicalTopDownError() {
    // clearContextSetByName("AccessOperationGetFlightOffers"); // modify access policies -->
    // // only
    // // one fail possible
    // getContextSetByName("AccessOperationGetFlightOffers").getContexts().add(getContextAttributeByName("root"));
    //
    // final var output = this.analysis.runScenarioAnalysis(this.blackBoard, this.context,
    // this.configuration);
    // assertNotNull(output.getScenariooutput());
    //
    // assertTrue(getScenarioResultByName(output, "AdministrationCreditCardData"));
    // final var listOutput = getScenariosByName(output, "defaultUsageScenario");
    // assertEquals(1, listOutput.size());
    // for (final var scenario : listOutput) {
    // assertFalse(scenario.isResult());
    // }
    // }
    //
    // @Test
    // @DisplayName("06_h_tp_2_layers")
    // void hierachicalTopDown2() {
    // clearContextSetByName("UsageGetFlight");
    // getContextSetByName("UsageGetFlight").getContexts().add(getContextAttributeByName("root"));
    //
    // // insert middlde element to root
    // final var contextRoot = getContextAttributeByName("root");
    // final var middleContext = createHierarchicalContext("Middle");
    // middleContext.setDirection(IncludeDirection.TOP_DOWN);
    // middleContext.getIncluding().add(getContextAttributeByName("Customer"));
    // middleContext.setContexttype(contextRoot.getContexttype());
    // this.context.getContextContainer().get(0).getContext().add(middleContext);
    // ((HierarchicalContext) contextRoot).getIncluding().clear();
    // ((HierarchicalContext) contextRoot).getIncluding().add(middleContext);
    //
    // final var output = this.analysis.runScenarioAnalysis(this.blackBoard, this.context,
    // this.configuration);
    // assertAllPositive(output);
    // }
    //

    //
    // @Test
    // @DisplayName("07_h_tp_2_l_error")
    // void hierachicalTopDown2Error() {
    // clearContextSetByName("AccessOperationGetFlightOffers"); // modify access policies -->
    // // only
    // // one fail possible
    // getContextSetByName("AccessOperationGetFlightOffers").getContexts().add(getContextAttributeByName("root"));
    //
    // // insert middlde element to root
    // final var contextRoot = getContextAttributeByName("root");
    // final var middleContext = createHierarchicalContext("Middle");
    // middleContext.setDirection(IncludeDirection.TOP_DOWN);
    // middleContext.getIncluding().add(getContextAttributeByName("Customer"));
    // middleContext.setContexttype(contextRoot.getContexttype());
    // this.context.getContextContainer().get(0).getContext().add(middleContext);
    // ((HierarchicalContext) contextRoot).getIncluding().clear();
    // ((HierarchicalContext) contextRoot).getIncluding().add(middleContext);
    //
    // final var output = this.analysis.runScenarioAnalysis(this.blackBoard, this.context,
    // this.configuration);
    // assertNotNull(output.getScenariooutput());
    //
    // assertTrue(getScenarioResultByName(output, "AdministrationCreditCardData"));
    // final var listOutput = getScenariosByName(output, "defaultUsageScenario");
    // assertEquals(1, listOutput.size());
    // for (final var scenario : listOutput) {
    // assertFalse(scenario.isResult());
    // }
    // }
    //
    // @Test
    // @DisplayName("08_h_tp_2_children")
    // void hierachicalTopDownC() {
    // clearContextSetByName("UsageGetFlight");
    // getContextSetByName("UsageGetFlight").getContexts().add(getContextAttributeByName("root"));
    //
    // // insert middlde element to root
    // final var contextRoot = getContextAttributeByName("root");
    // final var child2 = createHierarchicalContext("Child");
    // child2.setDirection(IncludeDirection.TOP_DOWN);
    // child2.setContexttype(contextRoot.getContexttype());
    // this.context.getContextContainer().get(0).getContext().add(child2);
    // ((HierarchicalContext) contextRoot).getIncluding().add(child2);
    //
    // final var output = this.analysis.runScenarioAnalysis(this.blackBoard, this.context,
    // this.configuration);
    // assertAllPositive(output);
    // }
    //
    // @Test
    // @DisplayName("09_h_tp_2_c_error")
    // void hierachicalTopDownCError() {
    // clearContextSetByName("UsageGetFlight");
    //
    // // insert middlde element to root
    // final var contextRoot = getContextAttributeByName("root");
    // final var child2 = createHierarchicalContext("Child");
    // child2.setDirection(IncludeDirection.TOP_DOWN);
    // child2.setContexttype(contextRoot.getContexttype());
    // this.context.getContextContainer().get(0).getContext().add(child2);
    // ((HierarchicalContext) contextRoot).getIncluding().add(child2);
    // getContextSetByName("UsageGetFlight").getContexts().add(child2);
    //
    // final var output = this.analysis.runScenarioAnalysis(this.blackBoard, this.context,
    // this.configuration);
    //
    // assertTrue(getScenarioResultByName(output, "AdministrationCreditCardData"));
    // final var listOutput = getScenariosByName(output, "defaultUsageScenario");
    // assertEquals(3, listOutput.size());
    // for (final var scenario : listOutput) {
    // assertFalse(scenario.isResult());
    // }
    // }
    //
    // @Test
    // @DisplayName("10_h_bottom_up")
    // void hierachicalBottomUp() {
    // // create Bottom Up Value HomeCity
    // final var homeCity = createHierarchicalContext("Home-City");
    // homeCity.setDirection(IncludeDirection.BOTTOM_UP);
    // homeCity.setContexttype(getContextAttributeByName("Home").getContexttype());
    // homeCity.getIncluding().add(getContextAttributeByName("Home"));
    //
    // clearContextSetByName("AccessOperationSetDeclassified");
    // getContextSetByName("AccessOperationSetDeclassified").getContexts().add(homeCity);
    // getContextSetByName("AccessOperationSetDeclassified").getContexts().add(getContextAttributeByName("Customer"));
    //
    // final var output = this.analysis.runScenarioAnalysis(this.blackBoard, this.context,
    // this.configuration);
    // assertAllPositive(output);
    // }
    //
    // @Test
    // @DisplayName("11_h_b_u_error")
    // void hierachicalBottomUpError() {
    // // create Bottom Up Value HomeCity
    // final var homeCity = createHierarchicalContext("Home-City");
    // homeCity.setDirection(IncludeDirection.BOTTOM_UP);
    // homeCity.setContexttype(getContextAttributeByName("Home").getContexttype());
    // homeCity.getIncluding().add(getContextAttributeByName("Home"));
    //
    // clearContextSetByName("UsageReleaseCCD");
    // getContextSetByName("UsageReleaseCCD").getContexts().add(homeCity);
    // getContextSetByName("UsageReleaseCCD").getContexts().add(getContextAttributeByName("Customer"));
    //
    // final var output = this.analysis.runScenarioAnalysis(this.blackBoard, this.context,
    // this.configuration);
    //
    // assertTrue(getScenarioResultByName(output, "AdministrationCreditCardData"));
    // final var listOutput = getScenariosByName(output, "defaultUsageScenario");
    // assertEquals(1, listOutput.size());
    // for (final var scenario : listOutput) {
    // assertFalse(scenario.isResult());
    // }
    // }
    //
    // @Test
    // @DisplayName("12_h_b_u_2_layers")
    // void hierachicalBottomUp2() {
    // // create Bottom Up Value HomeState
    // final var homeCity = createHierarchicalContext("Home-City");
    // homeCity.setDirection(IncludeDirection.BOTTOM_UP);
    // homeCity.setContexttype(getContextAttributeByName("Home").getContexttype());
    // homeCity.getIncluding().add(getContextAttributeByName("Home"));
    //
    // final var homeState = createHierarchicalContext("Home-State");
    // homeState.setDirection(IncludeDirection.BOTTOM_UP);
    // homeState.setContexttype(homeCity.getContexttype());
    // homeState.getIncluding().add(homeCity);
    //
    // clearContextSetByName("AccessOperationSetDeclassified");
    // getContextSetByName("AccessOperationSetDeclassified").getContexts().add(homeState);
    // getContextSetByName("AccessOperationSetDeclassified").getContexts().add(getContextAttributeByName("Customer"));
    //
    // final var output = this.analysis.runScenarioAnalysis(this.blackBoard, this.context,
    // this.configuration);
    // assertAllPositive(output);
    // }
    //
    // @Test
    // @DisplayName("13_h_b_u_2_l_error")
    // void hierachicalBottomUp2E() {
    //
    // // create Bottom Up Value HomeState
    // final var homeCity = createHierarchicalContext("Home-City");
    // homeCity.setDirection(IncludeDirection.BOTTOM_UP);
    // homeCity.setContexttype(getContextAttributeByName("Home").getContexttype());
    // homeCity.getIncluding().add(getContextAttributeByName("Home"));
    //
    // final var homeState = createHierarchicalContext("Home-State");
    // homeState.setDirection(IncludeDirection.BOTTOM_UP);
    // homeState.setContexttype(homeCity.getContexttype());
    // homeState.getIncluding().add(homeCity);
    //
    // clearContextSetByName("UsageReleaseCCD");
    // getContextSetByName("UsageReleaseCCD").getContexts().add(homeState);
    // getContextSetByName("UsageReleaseCCD").getContexts().add(getContextAttributeByName("Customer"));
    //
    // final var output = this.analysis.runScenarioAnalysis(this.blackBoard, this.context,
    // this.configuration);
    //
    // assertTrue(getScenarioResultByName(output, "AdministrationCreditCardData"));
    // final var listOutput = getScenariosByName(output, "defaultUsageScenario");
    // assertEquals(1, listOutput.size());
    // for (final var scenario : listOutput) {
    // assertFalse(scenario.isResult());
    // }
    // }
    //
    // @Test
    // @DisplayName("14_h_b_u_2_children")
    // void hierachicalBottomUp2child() {
    //
    // // create Bottom Up Value HomeState
    // final var homeCity = createHierarchicalContext("Home-City");
    // homeCity.setDirection(IncludeDirection.BOTTOM_UP);
    // homeCity.setContexttype(getContextAttributeByName("Home").getContexttype());
    // homeCity.getIncluding().add(getContextAttributeByName("Home"));
    //
    // final var friend = createSingleContext("FriendsHome");
    // friend.setContexttype(homeCity.getContexttype());
    //
    // homeCity.getIncluding().add(friend);
    //
    // clearContextSetByName("AccessOperationSetDeclassified");
    // getContextSetByName("AccessOperationSetDeclassified").getContexts().add(homeCity);
    // getContextSetByName("AccessOperationSetDeclassified").getContexts().add(getContextAttributeByName("Customer"));
    //
    // final var output = this.analysis.runScenarioAnalysis(this.blackBoard, this.context,
    // this.configuration);
    // assertAllPositive(output);
    // }
    //
    // @Test
    // @DisplayName("15_h_b_u_2_c_error")
    // void hierachicalBottomUp2childError() {
    //
    // // create Bottom Up Value HomeState
    // final var homeCity = createHierarchicalContext("Home-City");
    // homeCity.setDirection(IncludeDirection.BOTTOM_UP);
    // homeCity.setContexttype(getContextAttributeByName("Home").getContexttype());
    // homeCity.getIncluding().add(getContextAttributeByName("Home"));
    //
    // final var friend = createSingleContext("FriendsHome");
    // friend.setContexttype(homeCity.getContexttype());
    //
    // homeCity.getIncluding().add(friend);
    //
    // clearContextSetByName("UsageReleaseCCD");
    // getContextSetByName("UsageReleaseCCD").getContexts().add(homeCity);
    // getContextSetByName("UsageReleaseCCD").getContexts().add(getContextAttributeByName("Customer"));
    //
    // final var output = this.analysis.runScenarioAnalysis(this.blackBoard, this.context,
    // this.configuration);
    //
    // assertTrue(getScenarioResultByName(output, "AdministrationCreditCardData"));
    // final var listOutput = getScenariosByName(output, "defaultUsageScenario");
    // assertEquals(1, listOutput.size());
    // for (final var scenario : listOutput) {
    // assertFalse(scenario.isResult());
    // }
    // }
    //
    // @Test
    // @DisplayName("16_related_context_set")
    // void relatedContextSet() {
    //
    // final var related = createRelatedContext("Related");
    // related.setContextset(getContextSetByName("UsageReleaseCCD"));
    // this.context.getContextContainer().get(0).getContext().add(related);
    //
    // getContextSetByName("AccessOperationSetDeclassified").getContexts().add(related);
    // getContextSetByName("UsageDeclassifyCCD").getContexts().add(related);
    //
    // final var output = this.analysis.runScenarioAnalysis(this.blackBoard, this.context,
    // this.configuration);
    // assertAllPositive(output);
    // }
    //
    // @Test
    // @DisplayName("17_r_c_s_error")
    // void relatedContextSetError() {
    //
    // final var related = createRelatedContext("Related");
    // related.setContextset(getContextSetByName("UsageReleaseCCD"));
    // this.context.getContextContainer().get(0).getContext().add(related);
    //
    // getContextSetByName("AccessOperationSetDeclassified").getContexts().add(related);
    //
    // final var output = this.analysis.runScenarioAnalysis(this.blackBoard, this.context,
    // this.configuration);
    //
    // assertTrue(getScenarioResultByName(output, "AdministrationCreditCardData"));
    // final var listOutput = getScenariosByName(output, "defaultUsageScenario");
    // assertEquals(1, listOutput.size());
    // for (final var scenario : listOutput) {
    // assertFalse(scenario.isResult());
    // }
    // }
    //
    // @Test
    // @DisplayName("18_missusage") // no authentification from user only home
    // void misusage() {
    //
    // getSpecificationByName("UsageAdministrationCreditCardData").setMissageUse(true);
    // clearContextSetByName("UsageAdministrationCreditCardData");
    // getContextSetByName("UsageAdministrationCreditCardData").getContexts().add(getContextAttributeByName("Home"));
    //
    // final var output = this.analysis.runScenarioAnalysis(this.blackBoard, this.context,
    // this.configuration);
    // assertAllPositive(output);
    // }
    //
    // @Test
    // @DisplayName("19_m_error")
    // void misusageError() {
    //
    // getSpecificationByName("UsageAdministrationCreditCardData").setMissageUse(true);
    //
    // final var output = this.analysis.runScenarioAnalysis(this.blackBoard, this.context,
    // this.configuration);
    //
    // assertTrue(getScenarioByName(output, "defaultUsageScenario").isResult());
    // assertFalse(getScenarioResultByName(output, "AdministrationCreditCardData"));
    // }
    //
    // @Test
    // @DisplayName("20_more_context_sets")
    // void multipleSets() {
    //
    // final var homeCity = createHierarchicalContext("Home-City");
    // homeCity.setDirection(IncludeDirection.BOTTOM_UP);
    // homeCity.setContexttype(getContextAttributeByName("Home").getContexttype());
    // homeCity.getIncluding().add(getContextAttributeByName("Home"));
    // this.context.getContextContainer().get(0).getContext().add(homeCity);
    //
    // getContextSetByName("UsageAdministrationCreditCardData").getContexts().add(getContextAttributeByName("root"));
    // getContextSetByName("UsageAdministrationCreditCardData").getContexts().add(homeCity);
    //
    // final var output = this.analysis.runScenarioAnalysis(this.blackBoard, this.context,
    // this.configuration);
    //
    // assertTrue(getScenarioByName(output, "defaultUsageScenario").isResult());
    // assertTrue(getScenarioResultByName(output, "AdministrationCreditCardData"));
    // }
    //
    // @Test
    // @DisplayName("21_mismatch")
    // void mismatch() {
    //
    // getContextSetByName("AccessOperationGetFlightOffersTravelAgencyAirline").getContexts()
    // .add(getContextAttributeByName("Home"));
    //
    // final var output = this.analysis.runScenarioAnalysis(this.blackBoard, this.context,
    // this.configuration);
    //
    // assertFalse(getScenarioByName(output, "defaultUsageScenario").isResult());
    // assertTrue(getScenarioResultByName(output, "AdministrationCreditCardData"));
    // }

}
