package edu.kit.ipd.sdq.kamp4attack.tests;

import static org.junit.Assert.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.palladiosimulator.pcm.confidentiality.context.model.ModelFactory;

import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

class AttackPreStepTest extends AbstractModelTest {

    private String contextID;

    AttackPreStepTest() {
        this.PATH_ATTACKER = "platform:/plugin/edu.kit.ipd.sdq.kamp4attack.tests/models/PreStepTest/My.attacker";
        this.PATH_ASSEMBLY = "platform:/plugin/edu.kit.ipd.sdq.kamp4attack.tests/models/PreStepTest/newAssembly.system";
        this.PATH_ALLOCATION = "platform:/plugin/edu.kit.ipd.sdq.kamp4attack.tests/models/PreStepTest/newAllocation.allocation";
        this.PATH_CONTEXT = "platform:/plugin/edu.kit.ipd.sdq.kamp4attack.tests/models/PreStepTest/My.context";
        this.PATH_MODIFICATION = "platform:/plugin/edu.kit.ipd.sdq.kamp4attack.tests/models/PreStepTest/My.kamp4attackmodificationmarks";
        this.PATH_REPOSITORY = "platform:/plugin/edu.kit.ipd.sdq.kamp4attack.tests/models/PreStepTest/newRepository.repository";
        this.PATH_USAGE = "platform:/plugin/edu.kit.ipd.sdq.kamp4attack.tests/models/PreStepTest/newUsageModel.usagemodel";
        this.PATH_RESOURCES = "platform:/plugin/edu.kit.ipd.sdq.kamp4attack.tests/models/PreStepTest/newResourceEnvironment.resourceenvironment";
    }

    @Override
    protected void execute() {
        final var testContext = ModelFactory.eINSTANCE.createSingleAttributeContext();
        testContext.setEntityName("TestValue");
        this.contextID = testContext.getId();
        this.attacker.getAttackers().getAttacker().get(0).getCredentials().clear();
        this.attacker.getAttackers().getAttacker().get(0).getCredentials().add(testContext);
    }

    @Test
    void testNoNullValue() {
        super.execute();
        final var steps = this.modification.getChangePropagationSteps();
        assertNotNull(steps);
    }

    @Test
    void testOnlyStartAssembly() {
        this.attacker.getAttackers().getAttacker().get(0).getCredentials().clear();
        super.execute();
        final var steps = this.modification.getChangePropagationSteps();

        final var assembly = ((CredentialChange) steps.get(0)).getCompromisedassembly().get(0).getAffectedElement();

        assertEquals("_oO9U8O2-Eeq6pfPMAIqEqg", assembly.getId());
        assertEquals(1, steps.size());
        assertEquals(1, ((CredentialChange) steps.get(0)).getCompromisedassembly().size());
        assertEquals(0, ((CredentialChange) steps.get(0)).getCompromisedresource().size());
        assertEquals(0, ((CredentialChange) steps.get(0)).getContextchange().size());

    }

    @Test
    void testOnlyStartContext() {
        this.attacker.getAttackers().getAttacker().get(0).getCompromisedComponents().clear();
        super.execute();
        final var steps = this.modification.getChangePropagationSteps();

        assertEquals(1, steps.size());
        assertEquals(0, ((CredentialChange) steps.get(0)).getCompromisedassembly().size());
        assertEquals(0, ((CredentialChange) steps.get(0)).getCompromisedresource().size());
        assertEquals(1, ((CredentialChange) steps.get(0)).getContextchange().size());
        assertEquals(this.contextID,
                ((CredentialChange) steps.get(0)).getContextchange().get(0).getAffectedElement().getId());
    }

    @Test
    @Disabled("unclear for what")
    void testOnlyStartResource() {
        this.attacker.getAttackers().getAttacker().get(0).getCredentials().clear();
        this.attacker.getAttackers().getAttacker().get(0).getCompromisedComponents().clear();
        final var dbResource = this.environment.getResourceContainer_ResourceEnvironment().stream()
                .filter(e -> e.getEntityName().equals("DatabaseMachine")).findAny().get();
        this.attacker.getAttackers().getAttacker().get(0).getCompromisedResources().add(dbResource);
        super.execute();
        final var steps = this.modification.getChangePropagationSteps();

        final var resource = ((CredentialChange) steps.get(0)).getCompromisedresource().get(0).getAffectedElement();

        assertEquals(1, steps.size());
        assertEquals(0, ((CredentialChange) steps.get(0)).getCompromisedassembly().size());
        assertEquals(1, ((CredentialChange) steps.get(0)).getCompromisedresource().size());
        assertEquals(0, ((CredentialChange) steps.get(0)).getContextchange().size());
        assertEquals("_E9_FMe2_Eeq6pfPMAIqEqg", resource.getId());

    }

}
