package org.palladiosimulator.pcm.confidentiality.context.analysis.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.util.List;
import java.util.stream.Collectors;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.AnalysisResults;
import org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.ScenarioOutput;
import org.palladiosimulator.pcm.confidentiality.context.analysis.tests.base.BaseTestScenario;
import org.palladiosimulator.pcm.confidentiality.context.model.ContextAttribute;
import org.palladiosimulator.pcm.confidentiality.context.model.HierarchicalContext;
import org.palladiosimulator.pcm.confidentiality.context.model.IncludeDirection;
import org.palladiosimulator.pcm.confidentiality.context.model.ModelFactory;
import org.palladiosimulator.pcm.confidentiality.context.model.RelatedContextSet;
import org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.api.PCMBlackBoard;
import org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.provider.ScenarioAnalysisImpl;
import org.palladiosimulator.pcm.confidentiality.context.set.ContextSet;
import org.palladiosimulator.pcm.confidentiality.context.specification.ContextSpecification;

class ScenarioTests extends BaseTestScenario {
    @Test
    @DisplayName("01_no_context_usage_model")
    void noContext() {
        var blackBoard = new PCMBlackBoard(assembly, repo, usage);
        var analysis = new ScenarioAnalysisImpl();
        //clear existing policies
        context.getSetContainer().stream().flatMap(e -> e.getPolicies().stream()).forEach(e -> e.getContexts().clear());

        var output = analysis.runScenarioAnalysis(blackBoard, context);
        assertNotNull(output.getScenariooutput());
        for (var scenario : output.getScenariooutput()) {
            assertFalse(scenario.isResult());
        }
    }

    @Test
    @DisplayName("02_context")
    void allPositive() {
        var blackBoard = new PCMBlackBoard(assembly, repo, usage);
        var analysis = new ScenarioAnalysisImpl();
        var output = analysis.runScenarioAnalysis(blackBoard, context);
        assertAllPositive(output);
    }

    @Test
    @DisplayName("03_wrong_context_type")
    void wrongType() {
        var blackBoard = new PCMBlackBoard(assembly, repo, usage);
        var analysis = new ScenarioAnalysisImpl();

        var contextAttribute = createSingleContext("Customer");
        context.getContextContainer().get(0).getContext().add(contextAttribute);
        clearContextSetByName("UsageGetFlight");// modify requestor contexts --> multiple fails
                                                // possible
        getContextSetByName("UsageGetFlight").getContexts().add(contextAttribute);

        var output = analysis.runScenarioAnalysis(blackBoard, context);
        assertNotNull(output.getScenariooutput());

        assertTrue(getScenarioResultByName(output, "AdministrationCreditCardData"));

        var listOutput = getScenariosByName(output, "defaultUsageScenario");
        assertEquals(3, listOutput.size());
        for (var scenario : listOutput) {
            assertFalse(scenario.isResult());
        }

    }

    @Test
    @DisplayName("04_hierachical_top_down")
    void hierachicalTopDown() {
        var blackBoard = new PCMBlackBoard(assembly, repo, usage);
        var analysis = new ScenarioAnalysisImpl();

        clearContextSetByName("UsageGetFlight");
        getContextSetByName("UsageGetFlight").getContexts().add(getContextAttributeByName("root"));

        var output = analysis.runScenarioAnalysis(blackBoard, context);
        assertAllPositive(output);
    }

    @Test
    @DisplayName("05_h_tp_error")
    void hierachicalTopDownError() {
        var blackBoard = new PCMBlackBoard(assembly, repo, usage);
        var analysis = new ScenarioAnalysisImpl();

        clearContextSetByName("AccessOperationGetFlightOffers"); // modify access policies --> only
                                                                 // one fail possible
        getContextSetByName("AccessOperationGetFlightOffers").getContexts().add(getContextAttributeByName("root"));

        var output = analysis.runScenarioAnalysis(blackBoard, context);
        assertNotNull(output.getScenariooutput());

        assertTrue(getScenarioResultByName(output, "AdministrationCreditCardData"));
        var listOutput = getScenariosByName(output, "defaultUsageScenario");
        assertEquals(1, listOutput.size());
        for (var scenario : listOutput) {
            assertFalse(scenario.isResult());
        }
    }

    @Test
    @DisplayName("06_h_tp_2_layers")
    void hierachicalTopDown2() {
        var blackBoard = new PCMBlackBoard(assembly, repo, usage);
        var analysis = new ScenarioAnalysisImpl();

        clearContextSetByName("UsageGetFlight");
        getContextSetByName("UsageGetFlight").getContexts().add(getContextAttributeByName("root"));

        // insert middlde element to root
        var contextRoot = getContextAttributeByName("root");
        var middleContext = createHierarchicalContext("Middle");
        middleContext.setDirection(IncludeDirection.TOP_DOWN);
        middleContext.getIncluding().add(getContextAttributeByName("Customer"));
        middleContext.setContexttype(contextRoot.getContexttype());
        context.getContextContainer().get(0).getContext().add(middleContext);
        ((HierarchicalContext) contextRoot).getIncluding().clear();
        ((HierarchicalContext) contextRoot).getIncluding().add(middleContext);

        var output = analysis.runScenarioAnalysis(blackBoard, context);
        assertAllPositive(output);
    }

    private void assertAllPositive(AnalysisResults output) {
        assertNotNull(output.getScenariooutput());

        for (var scenario : output.getScenariooutput()) {
            assertTrue(scenario.isResult());
        }
    }

    @Test
    @DisplayName("07_h_tp_2_l_error")
    void hierachicalTopDown2Error() {
        var blackBoard = new PCMBlackBoard(assembly, repo, usage);
        var analysis = new ScenarioAnalysisImpl();

        clearContextSetByName("AccessOperationGetFlightOffers"); // modify access policies --> only
                                                                 // one fail possible
        getContextSetByName("AccessOperationGetFlightOffers").getContexts().add(getContextAttributeByName("root"));

        // insert middlde element to root
        var contextRoot = getContextAttributeByName("root");
        var middleContext = createHierarchicalContext("Middle");
        middleContext.setDirection(IncludeDirection.TOP_DOWN);
        middleContext.getIncluding().add(getContextAttributeByName("Customer"));
        middleContext.setContexttype(contextRoot.getContexttype());
        context.getContextContainer().get(0).getContext().add(middleContext);
        ((HierarchicalContext) contextRoot).getIncluding().clear();
        ((HierarchicalContext) contextRoot).getIncluding().add(middleContext);

        var output = analysis.runScenarioAnalysis(blackBoard, context);
        assertNotNull(output.getScenariooutput());

        assertTrue(getScenarioResultByName(output, "AdministrationCreditCardData"));
        var listOutput = getScenariosByName(output, "defaultUsageScenario");
        assertEquals(1, listOutput.size());
        for (var scenario : listOutput) {
            assertFalse(scenario.isResult());
        }
    }

    @Test
    @DisplayName("08_h_tp_2_children")
    void hierachicalTopDownC() {
        var blackBoard = new PCMBlackBoard(assembly, repo, usage);
        var analysis = new ScenarioAnalysisImpl();

        clearContextSetByName("UsageGetFlight");
        getContextSetByName("UsageGetFlight").getContexts().add(getContextAttributeByName("root"));

        // insert middlde element to root
        var contextRoot = getContextAttributeByName("root");
        var child2 = createHierarchicalContext("Child");
        child2.setDirection(IncludeDirection.TOP_DOWN);
        child2.setContexttype(contextRoot.getContexttype());
        context.getContextContainer().get(0).getContext().add(child2);
        ((HierarchicalContext) contextRoot).getIncluding().add(child2);

        var output = analysis.runScenarioAnalysis(blackBoard, context);
        assertAllPositive(output);
    }

    @Test
    @DisplayName("09_h_tp_2_c_error")
    void hierachicalTopDownCError() {
        var blackBoard = new PCMBlackBoard(assembly, repo, usage);
        var analysis = new ScenarioAnalysisImpl();

        clearContextSetByName("UsageGetFlight");

        // insert middlde element to root
        var contextRoot = getContextAttributeByName("root");
        var child2 = createHierarchicalContext("Child");
        child2.setDirection(IncludeDirection.TOP_DOWN);
        child2.setContexttype(contextRoot.getContexttype());
        context.getContextContainer().get(0).getContext().add(child2);
        ((HierarchicalContext) contextRoot).getIncluding().add(child2);
        getContextSetByName("UsageGetFlight").getContexts().add(child2);

        var output = analysis.runScenarioAnalysis(blackBoard, context);

        assertTrue(getScenarioResultByName(output, "AdministrationCreditCardData"));
        var listOutput = getScenariosByName(output, "defaultUsageScenario");
        assertEquals(3, listOutput.size());
        for (var scenario : listOutput) {
            assertFalse(scenario.isResult());
        }
    }

    @Test
    @DisplayName("10_h_bottom_up")
    void hierachicalBottomUp() {
        var blackBoard = new PCMBlackBoard(assembly, repo, usage);
        var analysis = new ScenarioAnalysisImpl();

        // create Bottom Up Value HomeCity
        var homeCity = createHierarchicalContext("Home-City");
        homeCity.setDirection(IncludeDirection.BOTTOM_UP);
        homeCity.setContexttype(getContextAttributeByName("Home").getContexttype());
        homeCity.getIncluding().add(getContextAttributeByName("Home"));

        clearContextSetByName("AccessOperationSetDeclassified");
        getContextSetByName("AccessOperationSetDeclassified").getContexts().add(homeCity);
        getContextSetByName("AccessOperationSetDeclassified").getContexts().add(getContextAttributeByName("Customer"));

        var output = analysis.runScenarioAnalysis(blackBoard, context);
        assertAllPositive(output);
    }

    @Test
    @DisplayName("11_h_b_u_error")
    void hierachicalBottomUpError() {
        var blackBoard = new PCMBlackBoard(assembly, repo, usage);
        var analysis = new ScenarioAnalysisImpl();

        // create Bottom Up Value HomeCity
        var homeCity = createHierarchicalContext("Home-City");
        homeCity.setDirection(IncludeDirection.BOTTOM_UP);
        homeCity.setContexttype(getContextAttributeByName("Home").getContexttype());
        homeCity.getIncluding().add(getContextAttributeByName("Home"));

        clearContextSetByName("UsageReleaseCCD");
        getContextSetByName("UsageReleaseCCD").getContexts().add(homeCity);
        getContextSetByName("UsageReleaseCCD").getContexts().add(getContextAttributeByName("Customer"));

        var output = analysis.runScenarioAnalysis(blackBoard, context);

        assertTrue(getScenarioResultByName(output, "AdministrationCreditCardData"));
        var listOutput = getScenariosByName(output, "defaultUsageScenario");
        assertEquals(1, listOutput.size());
        for (var scenario : listOutput) {
            assertFalse(scenario.isResult());
        }
    }

    @Test
    @DisplayName("12_h_b_u_2_layers")
    void hierachicalBottomUp2() {
        var blackBoard = new PCMBlackBoard(assembly, repo, usage);
        var analysis = new ScenarioAnalysisImpl();

        // create Bottom Up Value HomeState
        var homeCity = createHierarchicalContext("Home-City");
        homeCity.setDirection(IncludeDirection.BOTTOM_UP);
        homeCity.setContexttype(getContextAttributeByName("Home").getContexttype());
        homeCity.getIncluding().add(getContextAttributeByName("Home"));

        var homeState = createHierarchicalContext("Home-State");
        homeState.setDirection(IncludeDirection.BOTTOM_UP);
        homeState.setContexttype(homeCity.getContexttype());
        homeState.getIncluding().add(homeCity);

        clearContextSetByName("AccessOperationSetDeclassified");
        getContextSetByName("AccessOperationSetDeclassified").getContexts().add(homeState);
        getContextSetByName("AccessOperationSetDeclassified").getContexts().add(getContextAttributeByName("Customer"));

        var output = analysis.runScenarioAnalysis(blackBoard, context);
        assertAllPositive(output);
    }

    @Test
    @DisplayName("13_h_b_u_2_l_error")
    void hierachicalBottomUp2E() {
        var blackBoard = new PCMBlackBoard(assembly, repo, usage);
        var analysis = new ScenarioAnalysisImpl();

        // create Bottom Up Value HomeState
        var homeCity = createHierarchicalContext("Home-City");
        homeCity.setDirection(IncludeDirection.BOTTOM_UP);
        homeCity.setContexttype(getContextAttributeByName("Home").getContexttype());
        homeCity.getIncluding().add(getContextAttributeByName("Home"));

        var homeState = createHierarchicalContext("Home-State");
        homeState.setDirection(IncludeDirection.BOTTOM_UP);
        homeState.setContexttype(homeCity.getContexttype());
        homeState.getIncluding().add(homeCity);

        clearContextSetByName("UsageReleaseCCD");
        getContextSetByName("UsageReleaseCCD").getContexts().add(homeState);
        getContextSetByName("UsageReleaseCCD").getContexts().add(getContextAttributeByName("Customer"));

        var output = analysis.runScenarioAnalysis(blackBoard, context);

        assertTrue(getScenarioResultByName(output, "AdministrationCreditCardData"));
        var listOutput = getScenariosByName(output, "defaultUsageScenario");
        assertEquals(1, listOutput.size());
        for (var scenario : listOutput) {
            assertFalse(scenario.isResult());
        }
    }

    @Test
    @DisplayName("14_h_b_u_2_children")
    void hierachicalBottomUp2child() {
        var blackBoard = new PCMBlackBoard(assembly, repo, usage);
        var analysis = new ScenarioAnalysisImpl();

        // create Bottom Up Value HomeState
        var homeCity = createHierarchicalContext("Home-City");
        homeCity.setDirection(IncludeDirection.BOTTOM_UP);
        homeCity.setContexttype(getContextAttributeByName("Home").getContexttype());
        homeCity.getIncluding().add(getContextAttributeByName("Home"));

        var friend = createSingleContext("FriendsHome");
        friend.setContexttype(homeCity.getContexttype());

        homeCity.getIncluding().add(friend);

        clearContextSetByName("AccessOperationSetDeclassified");
        getContextSetByName("AccessOperationSetDeclassified").getContexts().add(homeCity);
        getContextSetByName("AccessOperationSetDeclassified").getContexts().add(getContextAttributeByName("Customer"));

        var output = analysis.runScenarioAnalysis(blackBoard, context);
        assertAllPositive(output);
    }

    @Test
    @DisplayName("15_h_b_u_2_c_error")
    void hierachicalBottomUp2childError() {
        var blackBoard = new PCMBlackBoard(assembly, repo, usage);
        var analysis = new ScenarioAnalysisImpl();

        // create Bottom Up Value HomeState
        var homeCity = createHierarchicalContext("Home-City");
        homeCity.setDirection(IncludeDirection.BOTTOM_UP);
        homeCity.setContexttype(getContextAttributeByName("Home").getContexttype());
        homeCity.getIncluding().add(getContextAttributeByName("Home"));

        var friend = createSingleContext("FriendsHome");
        friend.setContexttype(homeCity.getContexttype());

        homeCity.getIncluding().add(friend);

        clearContextSetByName("UsageReleaseCCD");
        getContextSetByName("UsageReleaseCCD").getContexts().add(homeCity);
        getContextSetByName("UsageReleaseCCD").getContexts().add(getContextAttributeByName("Customer"));

        var output = analysis.runScenarioAnalysis(blackBoard, context);

        assertTrue(getScenarioResultByName(output, "AdministrationCreditCardData"));
        var listOutput = getScenariosByName(output, "defaultUsageScenario");
        assertEquals(1, listOutput.size());
        for (var scenario : listOutput) {
            assertFalse(scenario.isResult());
        }
    }

    @Test
    @DisplayName("16_related_context_set")
    void relatedContextSet() {
        var blackBoard = new PCMBlackBoard(assembly, repo, usage);
        var analysis = new ScenarioAnalysisImpl();

        var related = createRelatedContext("Related");
        related.setContextset(getContextSetByName("UsageReleaseCCD"));
        context.getContextContainer().get(0).getContext().add(related);

        getContextSetByName("AccessOperationSetDeclassified").getContexts().add(related);
        getContextSetByName("UsageDeclassifyCCD").getContexts().add(related);

        var output = analysis.runScenarioAnalysis(blackBoard, context);
        assertAllPositive(output);
    }

    @Test
    @DisplayName("17_r_c_s_error")
    void relatedContextSetError() {
        var blackBoard = new PCMBlackBoard(assembly, repo, usage);
        var analysis = new ScenarioAnalysisImpl();

        var related = createRelatedContext("Related");
        related.setContextset(getContextSetByName("UsageReleaseCCD"));
        context.getContextContainer().get(0).getContext().add(related);

        getContextSetByName("AccessOperationSetDeclassified").getContexts().add(related);

        var output = analysis.runScenarioAnalysis(blackBoard, context);

        assertTrue(getScenarioResultByName(output, "AdministrationCreditCardData"));
        var listOutput = getScenariosByName(output, "defaultUsageScenario");
        assertEquals(1, listOutput.size());
        for (var scenario : listOutput) {
            assertFalse(scenario.isResult());
        }
    }

    @Test
    @DisplayName("18_missusage") // no authentification from user only home
    void misusage() {
        var blackBoard = new PCMBlackBoard(assembly, repo, usage);
        var analysis = new ScenarioAnalysisImpl();

        getSpecificationByName("UsageAdministrationCreditCardData").setMissageUse(true);
        clearContextSetByName("UsageAdministrationCreditCardData");
        getContextSetByName("UsageAdministrationCreditCardData").getContexts().add(getContextAttributeByName("Home"));

        var output = analysis.runScenarioAnalysis(blackBoard, context);
        assertAllPositive(output);
    }

    @Test
    @DisplayName("19_m_error")
    void misusageError() {
        var blackBoard = new PCMBlackBoard(assembly, repo, usage);
        var analysis = new ScenarioAnalysisImpl();

        getSpecificationByName("UsageAdministrationCreditCardData").setMissageUse(true);

        var output = analysis.runScenarioAnalysis(blackBoard, context);

        assertTrue(getScenarioByName(output, "defaultUsageScenario").isResult());
        assertFalse(getScenarioResultByName(output, "AdministrationCreditCardData"));
    }

    @Test
    @DisplayName("20_more_context_sets")
    void multipleSets() {
        var blackBoard = new PCMBlackBoard(assembly, repo, usage);
        var analysis = new ScenarioAnalysisImpl();

        var homeCity = createHierarchicalContext("Home-City");
        homeCity.setDirection(IncludeDirection.BOTTOM_UP);
        homeCity.setContexttype(getContextAttributeByName("Home").getContexttype());
        homeCity.getIncluding().add(getContextAttributeByName("Home"));
        context.getContextContainer().get(0).getContext().add(homeCity);

        getContextSetByName("UsageAdministrationCreditCardData").getContexts().add(getContextAttributeByName("root"));
        getContextSetByName("UsageAdministrationCreditCardData").getContexts().add(homeCity);

        var output = analysis.runScenarioAnalysis(blackBoard, context);

        assertTrue(getScenarioByName(output, "defaultUsageScenario").isResult());
        assertTrue(getScenarioResultByName(output, "AdministrationCreditCardData"));
    }

    @Test
    @DisplayName("21_mismatch")
    void mismatch() {
        var blackBoard = new PCMBlackBoard(assembly, repo, usage);
        var analysis = new ScenarioAnalysisImpl();

        getContextSetByName("AccessOperationGetFlightOffersTravelAgencyAirline").getContexts()
                .add(getContextAttributeByName("Home"));

        var output = analysis.runScenarioAnalysis(blackBoard, context);

        assertFalse(getScenarioByName(output, "defaultUsageScenario").isResult());
        assertTrue(getScenarioResultByName(output, "AdministrationCreditCardData"));
    }

    private ContextAttribute getContextAttributeByName(String name) {
        var contextAttribute = context.getContextContainer().stream().flatMap(e -> e.getContext().stream())
                .filter(e -> name.equals(e.getEntityName())).findAny();
        if (contextAttribute.isEmpty()) {
            fail("ContextAttribute with name " + name + " not found");
        }
        return contextAttribute.get();
    }

    private ContextSpecification getSpecificationByName(String name) {
        var specification = context.getPcmspecificationcontainer().getContextspecification().stream()
                .filter(e -> name.equals(e.getEntityName())).findAny();
        if (specification.isEmpty())
            fail("Specification with name " + name + " not found");
        return specification.get();
    }

    private boolean getScenarioResultByName(AnalysisResults results, String name) {
        var scenario = getScenarioByName(results, name);
        return scenario.isResult();
    }

    private List<ScenarioOutput> getScenariosByName(AnalysisResults results, String name) {
        return results.getScenariooutput().stream().filter(e -> e.getScenario().getEntityName().equals(name))
                .collect(Collectors.toList());
    }

    private ScenarioOutput getScenarioByName(AnalysisResults results, String name) {
        var output = results.getScenariooutput().stream().filter(e -> e.getScenario().getEntityName().equals(name))
                .findAny();
        if (output.isEmpty())
            fail("Scenario with name " + name + " not found");
        return output.get();
    }

    private void clearContextSetByName(String name) {
        var set = getContextSetByName(name);
        set.getContexts().clear();
    }

    private ContextSet getContextSetByName(String name) {
        var set = context.getSetContainer().stream().flatMap(e -> e.getPolicies().stream())
                .filter(e -> name.equals(e.getEntityName())).findAny();
        if (set.isEmpty())
            fail("Contextset with name " + name + " not found");
        return set.get();
    }

    private ContextAttribute createSingleContext(String name) {
        var context = ModelFactory.eINSTANCE.createSingleAttributeContext();
        context.setEntityName(name);
        return context;
    }

    private HierarchicalContext createHierarchicalContext(String name) {
        var context = ModelFactory.eINSTANCE.createHierarchicalContext();
        context.setEntityName(name);
        return context;
    }

    private RelatedContextSet createRelatedContext(String name) {
        var context = ModelFactory.eINSTANCE.createRelatedContextSet();
        context.setEntityName(name);
        return context;

    }
}
