package edu.kit.ipd.sdq.kamp4attack.tests.mitigation.extension.casestudies.travelplanner;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

public class EncryptionWithoutAttack extends MitigationTravelPlanner {

    public EncryptionWithoutAttack() {
        this.PATH_ATTACKER = "mitigationModels/compositeTravelPlanner/tests/02/test_model.attacker";
        this.PATH_CONTEXT = "mitigationModels/compositeTravelPlanner/tests/02/test_model.context";
        this.PATH_MODIFICATION = "mitigationModels/compositeTravelPlanner/tests/02/test_model.kamp4attackmodificationmarks";
    }

    @Test
    void noPropagation() {
        runAnalysis();

        var change = getCredentials();

        assertEquals(1, change.getCompromisedassembly().size());
        assertEquals(2, change.getCompromiseddata().size()); //6 without mitigation
    }


}
