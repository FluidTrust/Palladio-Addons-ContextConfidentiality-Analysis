package edu.kit.ipd.sdq.kamp4attack.tests.casestudies;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;
import edu.kit.ipd.sdq.kamp4attack.tests.change.AbstractChangeTests;

public class TargetCaseStudyTests extends AbstractChangeTests {
    public TargetCaseStudyTests() {
        this.PATH_ATTACKER = "targetBreach/My.attacker";
        this.PATH_ASSEMBLY = "targetBreach/target.system";
        this.PATH_ALLOCATION = "targetBreach/target.allocation";
        this.PATH_CONTEXT = "targetBreach/target.context";
        this.PATH_MODIFICATION = "targetBreach/target.kamp4attackmodificationmarks";
        this.PATH_REPOSITORY = "targetBreach/target.repository";
        this.PATH_RESOURCES = "targetBreach/target.resourceenvironment";
    }

    @Test
    void defaultCase() {
        runAnalysis();
    }

    @Test
    void defaultCaseCorrectAssemblyNumber() {
        runAnalysis();
        final var change = (CredentialChange) this.modification.getChangePropagationSteps().get(0);
        assertEquals(7, change.getCompromisedassembly().size());
        assertEquals(8, change.getCompromisedservice().size());
        assertEquals(2, change.getContextchange().size());
    }


}
