package edu.kit.ipd.sdq.kamp4attack.tests.mitigation.extension.casestudies.travelplanner;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

public class EmptyAttackerWithMitigation extends MitigationTravelPlanner {

    public EmptyAttackerWithMitigation() {
        this.PATH_ATTACKER = "mitigationModels/compositeTravelPlanner/tests/01/test_model.attacker";
        this.PATH_CONTEXT = "mitigationModels/compositeTravelPlanner/tests/01/test_model.context";
        this.PATH_MODIFICATION = "mitigationModels/compositeTravelPlanner/tests/01/test_model.kamp4attackmodificationmarks";

    }

    @Test
    void noPropagation() {
        runAnalysis();

        var change = getCredentials();

        assertEquals(0, change.getCompromisedassembly().size());
        assertEquals(0, change.getCompromisedlinkingresource().size());
        assertEquals(0, change.getCompromisedresource().size());
        assertEquals(0, change.getCompromisedservice().size());
        assertEquals(0, change.getContextchange().size());

//        var attacker = getBlackboardWrapper().getModificationMarkRepository().getSeedModifications()
//                .getAttackcomponent().get(0).getAffectedElement();

        assertEquals(0, change.getCompromiseddata().size());

    }

}
