package edu.kit.ipd.sdq.kamp4attack.tests.casestudies.travelplanner;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

public class EmptyAttackerTests extends TravelPlannerCaseStudy {

    public EmptyAttackerTests() {
        this.PATH_ATTACKER = "travelplanner/Attacker_Propagation_Accuracy/01/test_model.attacker";
        this.PATH_CONTEXT = "travelplanner/Attacker_Propagation_Accuracy/01/test_model.context";
        this.PATH_MODIFICATION = "travelplanner/Attacker_Propagation_Accuracy/01/test_model.kamp4attackmodificationmarks";

    }

    @Test
    void noPropagation() {
        this.runAnalysis();

        final var change = this.getCredentials();

        assertEquals(0, change.getCompromisedassembly()
            .size());
        assertEquals(0, change.getCompromisedlinkingresource()
            .size());
        assertEquals(0, change.getCompromisedresource()
            .size());
        assertEquals(0, change.getCompromisedservice()
            .size());
        assertEquals(0, change.getContextchange()
            .size());

        final var attacker = this.getBlackboardWrapper()
            .getModificationMarkRepository()
            .getSeedModifications()
            .getAttackcomponent()
            .get(0)
            .getAffectedElement();

        assertEquals(0, change.getCompromiseddata()
            .size());

    }

}
