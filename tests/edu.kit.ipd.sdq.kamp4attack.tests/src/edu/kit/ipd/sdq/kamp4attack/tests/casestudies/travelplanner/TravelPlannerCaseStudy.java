package edu.kit.ipd.sdq.kamp4attack.tests.casestudies.travelplanner;

import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

import org.junit.jupiter.api.Test;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;

import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedAssembly;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;
import edu.kit.ipd.sdq.kamp4attack.tests.change.AbstractChangeTests;

public abstract class TravelPlannerCaseStudy extends AbstractChangeTests {

    public TravelPlannerCaseStudy() {
        this.PATH_REPOSITORY = "travelplanner/default.repository";
        this.PATH_RESOURCES = "travelplanner/default.resourceenvironment";
        this.PATH_ASSEMBLY = "travelplanner/default.system";
        this.PATH_ALLOCATION = "travelplanner/default.allocation";
    }

    @Test
    void defaultCase() {
        runAnalysis();
    }

    protected CredentialChange getCredentials() {
        assertEquals(1, this.modification.getChangePropagationSteps().size());

        var change = this.modification.getChangePropagationSteps().get(0);

        assertTrue(change instanceof CredentialChange);

        return (CredentialChange) change;

    }

    protected boolean checkAssembly(CredentialChange change) {
        return change.getCompromisedassembly().stream().map(CompromisedAssembly::getAffectedElement)
                .map(AssemblyContext::getEntityName).allMatch(this::assemblyNameMatch);
    }

    protected boolean assemblyNameMatch(String name) {
        fail();
        return false;
    }

}
