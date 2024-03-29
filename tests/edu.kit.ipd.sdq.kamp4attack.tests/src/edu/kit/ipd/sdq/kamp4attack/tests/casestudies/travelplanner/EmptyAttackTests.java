package edu.kit.ipd.sdq.kamp4attack.tests.casestudies.travelplanner;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Set;

import org.junit.jupiter.api.Test;

public class EmptyAttackTests extends TravelPlannerCaseStudy {

    public EmptyAttackTests() {
        this.PATH_ATTACKER = "travelplanner/Attacker_Propagation_Accuracy/02/test_model.attacker";
        this.PATH_CONTEXT = "travelplanner/Attacker_Propagation_Accuracy/02/test_model.context";
        this.PATH_MODIFICATION = "travelplanner/Attacker_Propagation_Accuracy/02/test_model.kamp4attackmodificationmarks";
    }

    @Test
    void noPropagation() {
        this.runAnalysis();

        final var change = this.getCredentials();

        assertEquals(1, change.getCompromisedassembly()
            .size());
        assertEquals(0, change.getCompromisedlinkingresource()
            .size());
        assertEquals(0, change.getCompromisedresource()
            .size());
        assertEquals(3, change.getCompromisedservice()
            .size());
        assertEquals(0, change.getContextchange()
            .size());

        this.checkAssembly(change);

        final var attacker = this.getBlackboardWrapper()
            .getModificationMarkRepository()
            .getSeedModifications()
            .getAttackcomponent()
            .get(0)
            .getAffectedElement();

//FIXME: depends on the correct data handling or required connections
//        assertEquals(10, change.getCompromiseddata().size());

    }

    @Override
    protected boolean assemblyNameMatch(final String name) {
        final var set = Set.of("Travelplanner");
        return set.contains(name);
    }

}
