package edu.kit.ipd.sdq.kamp4attack.tests;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.stream.Collectors;

import org.junit.jupiter.api.Test;

import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.ContextChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;


class ModelsTest extends AbstractModelTest {
    
    @Test
    void testCorrectReturnTypes() {

        var steps = modification.getChangePropagationSteps();

        assertTrue(steps.stream().allMatch(CredentialChange.class::isInstance));
    }

    @Test
    void testNoNullValue() {
        var steps = modification.getChangePropagationSteps();
        assertNotNull(steps);
    }

    @Test
    void testCorrectReturnSize() {
        var steps = modification.getChangePropagationSteps();

        assertEquals(1, steps.size());
        assertEquals(1, ((CredentialChange) steps.get(0)).getCompromisedassembly().size());
        assertEquals(1, ((CredentialChange) steps.get(0)).getCompromisedresource().size());
        assertEquals(2, ((CredentialChange) steps.get(0)).getContextchange().size());
    }

    @Test
    void testCorrectReturnValues() {
        var steps = modification.getChangePropagationSteps();

        var resource = ((CredentialChange) steps.get(0)).getCompromisedresource().get(0).getAffectedElement();
        var assembly = ((CredentialChange) steps.get(0)).getCompromisedassembly().get(0).getAffectedElement();

        var contexts = ((CredentialChange) steps.get(0)).getContextchange().stream()
                .map(ContextChange::getAffectedElement).collect(Collectors.toList());
        assertEquals("_Fg8BQe2_Eeq6pfPMAIqEqg", resource.getId());
        assertEquals("_oO9U8O2-Eeq6pfPMAIqEqg", assembly.getId());

        var context0 = contexts.get(0);
        var context1 = contexts.get(1);

        assertTrue((context0.getId().equals("_XE-xsO29Eeq6pfPMAIqEqg")
                && context1.getId().equals("_abPi4O29Eeq6pfPMAIqEqg"))
                || (context1.getId().equals("_XE-xsO29Eeq6pfPMAIqEqg")
                        && context0.getId().equals("_abPi4O29Eeq6pfPMAIqEqg")));

    }

}
