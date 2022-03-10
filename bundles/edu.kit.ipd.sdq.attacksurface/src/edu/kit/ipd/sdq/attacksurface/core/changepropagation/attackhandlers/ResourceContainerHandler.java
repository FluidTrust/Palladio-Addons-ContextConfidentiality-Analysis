package edu.kit.ipd.sdq.attacksurface.core.changepropagation.attackhandlers;

import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import org.eclipse.emf.ecore.EObject;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data.DataHandlerAttacker;
import org.palladiosimulator.pcm.core.entity.Entity;
import org.palladiosimulator.pcm.resourceenvironment.ResourceContainer;

import edu.kit.ipd.sdq.attacksurface.graph.AttackGraph;
import edu.kit.ipd.sdq.attacksurface.graph.AttackStatusNodeContent;
import edu.kit.ipd.sdq.kamp4attack.core.api.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedResource;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

/**
 * Represents an abstract class for handling attacking of resource containers.
 * 
 * @author ugnwq
 * @version 1.0
 */
public abstract class ResourceContainerHandler extends AttackHandler {

    public ResourceContainerHandler(final BlackboardWrapper modelStorage, final DataHandlerAttacker dataHandler,
            final AttackGraph attackGraph) {
        super(modelStorage, dataHandler, attackGraph);
    }

    /**
     * Attacks the resources, compromising each newly compromised (new edge) resource.
     * 
     * @param containers - the resource
     * @param change - the changes
     * @param source - the attack source
     */
    public void attackResourceContainer(final Collection<ResourceContainer> containers, final CredentialChange change,
            final Entity source) {
        final var compromisedResources = containers.stream().map(e -> this.attackResourceContainer(e, change, source))
                .flatMap(Optional::stream).distinct().collect(Collectors.toList());
        final var newCompromisedResources = filterExistingEdges(compromisedResources, source);
        if (!newCompromisedResources.isEmpty()) {
            change.setChanged(true);
            final var selectedNodeBefore = getAttackGraph().getSelectedNode();
            final var attackSource = new AttackStatusNodeContent(source);
            
            for (final var newlyCompromised : newCompromisedResources) {
                final var compromisedNode = new AttackStatusNodeContent(newlyCompromised.getAffectedElement());
                final var causingElements = newlyCompromised.getCausingElements();
                compromise(causingElements, compromisedNode, attackSource);
            }
            getAttackGraph().setSelectedNode(selectedNodeBefore);
        }
    }

    /**
     * Attacks the given resource container from the given source with the correct way of attacking it
     * defined by the respective subclass.
     * 
     * @param container - the resource container
     * @param change - the changes
     * @param source - the given source
     * @return the compromised assembly or a {@code none} value if the assembly could not be compromised
     */
    protected abstract Optional<CompromisedResource> attackResourceContainer(ResourceContainer container,
            CredentialChange change, EObject source);

    private Collection<CompromisedResource> filterExistingEdges(
            final List<CompromisedResource> compromisedResources, final Entity source) {
        final var clazz = CompromisedResource.class;
        return filterExistingEdges(compromisedResources, source, clazz)
                .stream()
                .map(clazz::cast)
                .collect(Collectors.toList());
    }
}
