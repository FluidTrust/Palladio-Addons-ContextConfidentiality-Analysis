package edu.kit.ipd.sdq.attacksurface.core.changepropagation.attackhandlers;


import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.HelperCreationCompromisedElements;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data.DataHandlerAttacker;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.core.entity.Entity;

import edu.kit.ipd.sdq.attacksurface.graph.AttackGraph;
import edu.kit.ipd.sdq.attacksurface.graph.AttackStatusNodeContent;
import edu.kit.ipd.sdq.kamp4attack.core.api.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedAssembly;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

/**
 * Represents an abstract class for handling attacking of assembly contexts.
 *
 * @author ugnwq
 * @version 1.0
 */
public abstract class AssemblyContextHandler extends AttackHandler  {

    protected AssemblyContextHandler(final BlackboardWrapper modelStorage, final DataHandlerAttacker dataHandler,
            final AttackGraph attackGraph) {
        super(modelStorage, dataHandler, attackGraph);
    }

    /**
     * Attacks the assembly contexts, compromising each newly compromised (new edge) assembly context.
     *
     * @param components - the assembly contexts
     * @param change - the changes
     * @param source - the attack source
     * @param doesAttackComeFromContainingContainer
     *      - whether the attack comes from the containing resource container so that the assembly contexts are
     *      compromised without an additional attack
     */
    public void attackAssemblyContext(final List<List<AssemblyContext>> componenthierachy,
            final CredentialChange change,
            final Entity source, final boolean doesAttackComeFromContainingContainer) {
        var components = componenthierachy.get(0);
        final var compromisedComponents = components
                .stream()
                .map(e -> doesAttackComeFromContainingContainer
                        ? Optional.of(HelperCreationCompromisedElements.createCompromisedAssembly(e, List.of(source)))
                                : attackComponent(e, change, source)
                    )
                .flatMap(Optional::stream).collect(Collectors.toList());

        final var newCompromisedComponents = filterExistingEdges(compromisedComponents, source);
        if (!newCompromisedComponents.isEmpty()) {
            change.setChanged(true);
            final var selectedNodeBefore = getAttackGraph().getSelectedNode();
            final var attackSource = new AttackStatusNodeContent(source);
            for (final var newlyCompromised : newCompromisedComponents) {
                final var compromisedNode = new AttackStatusNodeContent(newlyCompromised.getAffectedElement());
                final var causingElements = newlyCompromised.getCausingElements();
                compromise(causingElements, compromisedNode, attackSource);
            }
            getAttackGraph().setSelectedNode(selectedNodeBefore);
        }
    }

    /**
     * Attacks the given assembly context from the given source with the correct way of attacking it
     * defined by the respective subclass.
     *
     * @param component - the assembly context
     * @param change - the changes
     * @param source - the given source
     * @return the compromised assembly or a {@code none} value if the assembly could not be comrpomised
     */
    protected abstract Optional<CompromisedAssembly> attackComponent(AssemblyContext component, CredentialChange change,
            Entity source);

    private Collection<CompromisedAssembly> filterExistingEdges(
            final List<CompromisedAssembly> compromisedComponents, final Entity source) {
        final var clazz = CompromisedAssembly.class;
        return filterExistingEdges(compromisedComponents, source, clazz)
                .stream()
                .map(clazz::cast)
                .collect(Collectors.toList());
    }
}
