package org.palladiosimulator.pcm.confidentiality.attacker.variation.statehandler.pcm;

import java.util.List;
import java.util.Map;

import org.eclipse.emf.ecore.EObject;

import UncertaintyVariationModel.VariationPoint;
import UncertaintyVariationModel.statehandler.GenericStateHandler;

public class StartComponentStateHandler extends GenericStateHandler {

    @Override
    public List<String> getModelTypes() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public int getSizeOfDimension(final VariationPoint variationPoint) {
        // TODO Auto-generated method stub
        return 0;
    }

    @Override
    public void patchModelWith(final Map<String, List<EObject>> models, final VariationPoint variationPoint,
            final int variationIdx) {
        // TODO Auto-generated method stub

    }

}
