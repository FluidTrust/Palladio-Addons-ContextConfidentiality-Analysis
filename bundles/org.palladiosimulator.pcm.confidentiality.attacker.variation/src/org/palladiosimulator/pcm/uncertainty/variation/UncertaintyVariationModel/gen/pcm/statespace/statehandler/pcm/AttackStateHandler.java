package org.palladiosimulator.pcm.uncertainty.variation.UncertaintyVariationModel.gen.pcm.statespace.statehandler.pcm;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.eclipse.emf.ecore.EObject;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.Attacker;

import UncertaintyVariationModel.PrimitiveValue;
import UncertaintyVariationModel.VariationPoint;
import UncertaintyVariationModel.statehandler.GenericStateHandler;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.AttackerSelection;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationRepository;

public class AttackStateHandler extends GenericStateHandler {

    @Override
    public int getSizeOfDimension(final VariationPoint variationPoint) {
        final var desc = variationPoint.getVariationDescription();
        return desc.getTargetVariations()
            .size();
    }

    @Override
    public void patchModelWith(final Map<String, List<EObject>> models, final VariationPoint variationPoint,
            final int variationIdx) {
        final var desc = variationPoint.getVariationDescription();
        for (final EObject container : models.get(MODEL_TYPE1)) {
            final var attacker = (KAMP4attackModificationRepository) container;
            final var vals = (PrimitiveValue) desc.getTargetVariations()
                .get(variationIdx);
            final var resolvedVariations = this.resolve(models.get(MODEL_TYPE2), vals.getLink());
            final var resolvedSubject = this.resolve(attacker,
                    variationPoint.getVaryingSubjects()
                .get(0));
            resolvedSubject.ifPresent(subject -> patch(subject, resolvedVariations));
        }

    }

    @Override
    public List<String> getModelTypes() {
        return Arrays.asList(MODEL_TYPE1, MODEL_TYPE2);
    }

    private void patch(final EObject element, final Optional<EObject> values) {
        final var resolved = (AttackerSelection) element;
        resolved.setAffectedElement(null);
        values.ifPresent(val -> {
            resolved.setAffectedElement((Attacker) val);
        });
    }

    private static final String MODEL_TYPE1 = "kamp4attackmodificationmarks";
    private static final String MODEL_TYPE2 = "attacker";

}
