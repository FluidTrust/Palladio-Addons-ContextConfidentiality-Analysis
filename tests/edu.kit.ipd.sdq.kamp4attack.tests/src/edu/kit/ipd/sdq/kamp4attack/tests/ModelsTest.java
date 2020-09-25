package edu.kit.ipd.sdq.kamp4attack.tests;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.stream.Collectors;

import org.junit.jupiter.api.Test;

import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.ContextChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

class ModelsTest extends AbstractModelTest {

    ModelsTest() {
        this.PATH_ATTACKER = "platform:/plugin/edu.kit.ipd.sdq.kamp4attack.tests/models/SimpleModelTest/My.attacker";
        this.PATH_ASSEMBLY = "platform:/plugin/edu.kit.ipd.sdq.kamp4attack.tests/models/SimpleModelTest/newAssembly.system";
        this.PATH_ALLOCATION = "platform:/plugin/edu.kit.ipd.sdq.kamp4attack.tests/models/SimpleModelTest/newAllocation.allocation";
        this.PATH_CONTEXT = "platform:/plugin/edu.kit.ipd.sdq.kamp4attack.tests/models/SimpleModelTest/My.context";
        this.PATH_MODIFICATION = "platform:/plugin/edu.kit.ipd.sdq.kamp4attack.tests/models/SimpleModelTest/My.kamp4attackmodificationmarks";
        this.PATH_REPOSITORY = "platform:/plugin/edu.kit.ipd.sdq.kamp4attack.tests/models/SimpleModelTest/newRepository.repository";
        this.PATH_USAGE = "platform:/plugin/edu.kit.ipd.sdq.kamp4attack.tests/models/SimpleModelTest/newUsageModel.usagemodel";
        this.PATH_RESOURCES = "platform:/plugin/edu.kit.ipd.sdq.kamp4attack.tests/models/SimpleModelTest/newResourceEnvironment.resourceenvironment";
    }

    @Test
    void testCorrectReturnSize() {
        final var steps = this.modification.getChangePropagationSteps();

        assertEquals(1, steps.size());
        assertEquals(1, ((CredentialChange) steps.get(0)).getCompromisedassembly().size());
        assertEquals(1, ((CredentialChange) steps.get(0)).getCompromisedresource().size());
        assertEquals(2, ((CredentialChange) steps.get(0)).getContextchange().size());
    }

    @Test
    void testCorrectReturnTypes() {

        final var steps = this.modification.getChangePropagationSteps();

        assertTrue(steps.stream().allMatch(CredentialChange.class::isInstance));
    }

    @Test
    void testCorrectReturnValues() {
        final var steps = this.modification.getChangePropagationSteps();

        final var resource = ((CredentialChange) steps.get(0)).getCompromisedresource().get(0).getAffectedElement();
        final var assembly = ((CredentialChange) steps.get(0)).getCompromisedassembly().get(0).getAffectedElement();

        final var contexts = ((CredentialChange) steps.get(0)).getContextchange().stream()
                .map(ContextChange::getAffectedElement).collect(Collectors.toList());
        assertEquals("_Fg8BQe2_Eeq6pfPMAIqEqg", resource.getId());
        assertEquals("_oO9U8O2-Eeq6pfPMAIqEqg", assembly.getId());

        final var context0 = contexts.get(0);
        final var context1 = contexts.get(1);

        assertTrue((context0.getId().equals("_XE-xsO29Eeq6pfPMAIqEqg")
                && context1.getId().equals("_abPi4O29Eeq6pfPMAIqEqg"))
                || (context1.getId().equals("_XE-xsO29Eeq6pfPMAIqEqg")
                        && context0.getId().equals("_abPi4O29Eeq6pfPMAIqEqg")));

    }

    @Test
    void testNoNullValue() {
        final var steps = this.modification.getChangePropagationSteps();
        assertNotNull(steps);
    }

}
