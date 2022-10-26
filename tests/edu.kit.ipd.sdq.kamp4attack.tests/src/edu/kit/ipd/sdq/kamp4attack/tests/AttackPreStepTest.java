package edu.kit.ipd.sdq.kamp4attack.tests;


import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.junit.jupiter.api.Test;

import edu.kit.ipd.sdq.kamp4attack.core.AttackPropagationAnalysis;

class AttackPreStepTest extends AbstractModelTest {

    AttackPreStepTest() {
        this.PATH_ATTACKER = "simpleAttackmodels/SimpleModelTest/My.attacker";
        this.PATH_ASSEMBLY = "simpleAttackmodels/SimpleModelTest/newAssembly.system";
        this.PATH_ALLOCATION = "simpleAttackmodels/SimpleModelTest/newAllocation.allocation";
        this.PATH_CONTEXT = "simpleAttackmodels/SimpleModelTest/My.context";
        this.PATH_MODIFICATION = "simpleAttackmodels/SimpleModelTest/My.kamp4attackmodificationmarks";
        this.PATH_REPOSITORY = "simpleAttackmodels/SimpleModelTest/newRepository.repository";
        this.PATH_USAGE = "simpleAttackmodels/SimpleModelTest/newUsageModel.usagemodel";
        this.PATH_RESOURCES = "simpleAttackmodels/SimpleModelTest/newResourceEnvironment.resourceenvironment";
    }

    protected void execute() {
        generateXML();
        final var wrapper = getBlackboardWrapper();
        (new AttackPropagationAnalysis()).runChangePropagationAnalysis(wrapper);
    }

    @Test
    void testNoNullValue() {
        execute();
        final var steps = this.modification.getChangePropagationSteps();
        assertNotNull(steps);
    }

    @Test
    void testOnlyStartAssembly() {
        this.attacker.getAttackers().getAttacker().get(0).getCredentials().clear();
        execute();
        final var steps = this.modification.getChangePropagationSteps();

        final var assembly = steps.get(0).getCompromisedassembly().get(0).getAffectedElement();

        assertEquals("_oO9U8O2-Eeq6pfPMAIqEqg", assembly.getId());
        assertEquals(1, steps.size());
        assertEquals(1, steps.get(0).getCompromisedassembly().size());
        assertEquals(0, steps.get(0).getCompromisedresource().size());
        assertEquals(0, steps.get(0).getContextchange().size());

    }

    @Test
    void testAttackerOnlyStartAttribute() {
        this.attacker.getAttackers().getAttacker().get(0).getCompromisedComponents().clear();

        var context = createContext("TestValue");

        this.attacker.getAttackers().getAttacker().get(0).getCredentials().clear();
        this.attacker.getAttackers().getAttacker().get(0).getCredentials().add(context);
        execute();
        final var steps = this.modification.getChangePropagationSteps();
        //
        assertEquals(1, steps.size());
        assertEquals(0, steps.get(0).getCompromisedassembly().size());
        assertEquals(0, steps.get(0).getCompromisedresource().size());
        assertEquals(1, steps.get(0).getContextchange().size());
        assertTrue(EcoreUtil.equals(context,
                steps.get(0).getContextchange().get(0).getAffectedElement()));
    }

}
