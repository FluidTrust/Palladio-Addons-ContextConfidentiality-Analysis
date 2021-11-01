package edu.kit.ipd.sdq.kamp4attack.tests.casestudies;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Set;

import org.junit.jupiter.api.Test;
import org.palladiosimulator.pcm.confidentiality.context.system.UsageSpecification;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;

import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedAssembly;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.ContextChange;
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
        assertEquals(9, change.getCompromisedservice().size());
        assertEquals(2, change.getContextchange().size());
        assertEquals(1, change.getCompromisedlinkingresource().size());
        assertEquals(5, change.getCompromisedresource().size());

        var containsAllAssemblies = change.getCompromisedassembly().stream()
                .map(CompromisedAssembly::getAffectedElement).map(AssemblyContext::getEntityName)
                .allMatch(this::assemblyNameMatch);

        var containsAllUsageSpecification = change.getContextchange().stream().map(ContextChange::getAffectedElement)
                .map(UsageSpecification::getEntityName).allMatch(this::usageSpecificationNameMatch);



        assertTrue(containsAllAssemblies, "Not the excpected Assemblies are compromised");
        assertTrue(containsAllUsageSpecification, "Not the expected UsageSpecifications are gathered");

    }

    private boolean assemblyNameMatch(String name) {
        var set = Set.of("Assembly_BusinessServiceComponent", "Assembly_POSComponent1", "Assembly_ExternalSupplier",
                "Assembly_Database", "Assembly_FTPComponent", "Assembly_POSComponent2", "Assembly_POSComponent3");
        return set.contains(name);
    }

    private boolean usageSpecificationNameMatch(String name) {
        var set = Set.of("UsageSupplier", "DomainAdmin");
        return set.contains(name);
    }



}
