package org.palladiosimulator.pcm.confidentiality.attacker.variation.statehandler.pcm;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.eclipse.emf.ecore.EObject;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.Attacker;

import UncertaintyVariationModel.VariationPoint;
import UncertaintyVariationModel.statehandler.GenericStateHandler;

public class StartComponentStateHandler extends GenericStateHandler {

	private static final String MODEL_TYPE1 = "attacker";
	private static final String MODEL_TYPE2 = "system	";

	@Override
	public List<String> getModelTypes() {
		return Arrays.asList(MODEL_TYPE1, MODEL_TYPE2);
	}

	@Override
	public int getSizeOfDimension(final VariationPoint variationPoint) {
		var assemblies = variationPoint.getVaryingSubjects();
		if (assemblies.isEmpty())
			throw new IllegalStateException("Varying subject list is empty");
		var system = (org.palladiosimulator.pcm.system.System) assemblies.get(0).eContainer();
		return system.getAssemblyContexts__ComposedStructure().size();
	}

	@Override
	public void patchModelWith(final Map<String, List<EObject>> models, final VariationPoint variationPoint,
			final int variationIdx) {
		final var desc = variationPoint.getVariationDescription();
		for (final var container : models.get(MODEL_TYPE1)) {
			final var attacker = (Attacker) container;
			
		}
	}

}
