package edu.kit.ipd.sdq.kamp4attack.tests.casestudies.travelplanner;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Set;

import org.junit.jupiter.api.Test;

public class CredentialsPropagationTests extends TravelPlannerCaseStudy {

    public CredentialsPropagationTests() {
        this.PATH_ATTACKER = "travelplanner/Attacker_Propagation_Accuracy/03/test_model.attacker";
        this.PATH_CONTEXT = "travelplanner/Attacker_Propagation_Accuracy/03/test_model.context";
        this.PATH_MODIFICATION = "travelplanner/Attacker_Propagation_Accuracy/03/test_model.kamp4attackmodificationmarks";
    }

    @Test
    void propagation() {
        runAnalysis();

        var change = getCredentials();

        assertEquals(2, change.getCompromisedassembly().size());
        assertEquals(0, change.getCompromisedlinkingresource().size());
        assertEquals(1, change.getCompromisedresource().size());
        assertEquals(6, change.getCompromisedservice().size());
        assertEquals(2, change.getContextchange().size());

        checkAssembly(change);

    }

    @Override
    protected boolean assemblyNameMatch(String name) {
        var set = Set.of("Travelplanner", "CreditCardCenter");
        return set.contains(name);
    }
}
