package org.palladiosimulator.pcm.confidentiality.attacker.variation.statehandler.pcm;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.eclipse.emf.ecore.EObject;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.Attacker;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.PcmIntegrationFactory;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;

import UncertaintyVariationModel.VariationPoint;
import UncertaintyVariationModel.statehandler.GenericStateHandler;

public class StartComponentStateHandler extends GenericStateHandler {

    private static final String MODEL_TYPE1 = "attacker";
    private static final String MODEL_TYPE2 = "system";

    @Override
    public List<String> getModelTypes() {
        return Arrays.asList(MODEL_TYPE1, MODEL_TYPE2);
    }

    @Override
    public int getSizeOfDimension(final VariationPoint variationPoint) {
        var assemblies = variationPoint.getVaryingSubjects();
        if (assemblies.isEmpty() || ((Attacker) assemblies.get(0)).getCompromisedComponents().isEmpty()) {
            throw new IllegalStateException("Varying subject list is empty");
        }
        var system = (org.palladiosimulator.pcm.system.System) ((Attacker) assemblies.get(0)).getCompromisedComponents()
                .get(0).eContainer();
        return system.getAssemblyContexts__ComposedStructure().size();
    }

    @Override
    public void patchModelWith(final Map<String, List<EObject>> models, final VariationPoint variationPoint,
            final int variationIdx) {
        for (final var container : models.get(MODEL_TYPE1)) {
            for (var currentSubject : variationPoint.getVaryingSubjects()) {
                var system = (org.palladiosimulator.pcm.system.System) models.get(MODEL_TYPE2).get(0);
                var resolvedComponent = this.resolve(system,
                        system.getAssemblyContexts__ComposedStructure().get(variationIdx));
                var resolvedAttacker = this.resolve(container, currentSubject);
                if (resolvedAttacker.isPresent() && resolvedComponent.isPresent()) {
                    var attacker = ((Attacker) resolvedAttacker.get());
                    attacker.getCompromisedComponents().clear();
                    var systemComponent = PcmIntegrationFactory.eINSTANCE.createSystemComponent();
                    systemComponent.getAssemblycontext().add((AssemblyContext) resolvedComponent.get());
                    attacker.getCompromisedComponents().add(systemComponent);
                }

            }
        }
    }

    @Override
    public String getValue(VariationPoint variationPoint, int variationIdx) {
        // TODO Auto-generated method stub
        return null;
    }

}
