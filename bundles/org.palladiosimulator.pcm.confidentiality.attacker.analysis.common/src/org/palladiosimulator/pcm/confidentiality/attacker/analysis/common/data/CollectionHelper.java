package org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.palladiosimulator.pcm.allocation.Allocation;
import org.palladiosimulator.pcm.allocation.AllocationContext;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.core.entity.Entity;
import org.palladiosimulator.pcm.resourceenvironment.ResourceContainer;

import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.ModifyEntity;

public class CollectionHelper {

    /**
     * Revmoves elements from a collection of {@link ModifyEntity} which already are affected
     * 
     * @param existingCollection
     * @param newCollection
     * @return
     */
    public static Collection<? extends ModifyEntity<? extends Entity>> removeAlreadyAffectedElements(
            Collection<? extends ModifyEntity<? extends Entity>> existingCollection,
            Collection<? extends ModifyEntity<? extends Entity>> newCollection) {
        return newCollection.stream()
                .filter(targetObject -> existingCollection.stream().noneMatch(referenceObject -> EcoreUtil
                        .equals(targetObject.getAffectedElement(), referenceObject.getAffectedElement())))
                .collect(Collectors.toList());

    }

    public static List<AssemblyContext> getAssemblyContext(List<ResourceContainer> reachableResources,
            Allocation allocation) {
        return allocation.getAllocationContexts_Allocation().stream()
                .filter(container -> searchResource(container.getResourceContainer_AllocationContext(),
                        reachableResources))
                .map(AllocationContext::getAssemblyContext_AllocationContext).distinct().collect(Collectors.toList());

    }

    private static boolean searchResource(ResourceContainer targetContainer, List<ResourceContainer> listContainer) {
        return listContainer.stream().anyMatch(container -> EcoreUtil.equals(container, targetContainer));
    }
}
