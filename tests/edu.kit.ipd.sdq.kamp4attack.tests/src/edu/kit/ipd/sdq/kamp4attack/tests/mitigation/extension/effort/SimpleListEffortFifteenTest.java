package edu.kit.ipd.sdq.kamp4attack.tests.mitigation.extension.effort;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import edu.kit.ipd.sdq.kamp4attack.core.AttackPropagationAnalysis;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;
import edu.kit.ipd.sdq.kamp4attack.tests.AbstractModelTest;

class SimpleListEffortFifteenTest extends AbstractModelTest {

	public SimpleListEffortFifteenTest() {
		this.PATH_ATTACKER = "contextSelectionModels/effortModels/simpleEffortModel/attacker/fifteenAttribute.attacker";
		this.PATH_ASSEMBLY = "contextSelectionModels/effortModels/simpleEffortModel/simpleEffort.system";
		this.PATH_ALLOCATION = "contextSelectionModels/effortModels/simpleEffortModel/simpleEffort.allocation";
		this.PATH_CONTEXT = "contextSelectionModels/effortModels/simpleEffortModel/effort.context";
		this.PATH_MODIFICATION = "contextSelectionModels/effortModels/simpleEffortModel/modificationmarks/fifteen.kamp4attackmodificationmarks";
		this.PATH_REPOSITORY = "contextSelectionModels/effortModels/simpleEffortModel/simpleEffort.repository";
		this.PATH_USAGE = "contextSelectionModels/effortModels/simpleEffortModel/simpleEffort.usagemodel";
		this.PATH_RESOURCES = "contextSelectionModels/effortModels/simpleEffortModel/simpleEffort.resourceenvironment";
	}

	@BeforeEach
	protected void execute() {
		generateXML();
		final var wrapper = getBlackboardWrapper();
		(new AttackPropagationAnalysis()).runChangePropagationAnalysis(wrapper);
	}

	@Test
	void testSimpleCaseFifteenAttribute() {
		final var steps = this.modification.getChangePropagationSteps();

		assertEquals(1, steps.size());
		assertEquals(1, ((CredentialChange) steps.get(0)).getCompromisedassembly().size());
	}
}
