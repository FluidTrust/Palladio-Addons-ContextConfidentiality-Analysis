package edu.kit.ipd.sdq.attacksurface.core.changepropagation.attackhandlers;

import java.util.Collection;
import java.util.Optional;
import java.util.stream.Collectors;

import org.eclipse.emf.ecore.EObject;
import org.eclipse.emf.ecore.util.EcoreUtil;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data.DataHandlerAttacker;
import org.palladiosimulator.pcm.resourceenvironment.LinkingResource;

import edu.kit.ipd.sdq.attacksurface.graph.AttackGraph;
import edu.kit.ipd.sdq.kamp4attack.core.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedLinkingResource;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

public abstract class LinkingResourceHandler extends AttackHandler {
    //TODO adapt

    protected LinkingResourceHandler(final BlackboardWrapper modelStorage, final DataHandlerAttacker dataHandler,
            final AttackGraph attackGraph) {
        super(modelStorage, dataHandler, attackGraph);
    }

    public void attackLinkingResource(final Collection<LinkingResource> linking, final CredentialChange change,
            final EObject source) {
        final var compromisedResources = linking.stream().map(e -> this.attackLinkingResource(e, change, source))
                .flatMap(Optional::stream).distinct().collect(Collectors.toList());
        final var newCompromisedResources = filterExsiting(compromisedResources, change);
        if (!newCompromisedResources.isEmpty()) {
            handleDataExtraction(newCompromisedResources);
            change.setChanged(true);
            //TODO remove and adapt change.getCompromisedlinkingresource().addAll(newCompromisedResources);
        }
    }

    private void handleDataExtraction(final Collection<CompromisedLinkingResource> linking) {
        // extension possible
        // consider dataflow
    }

    protected abstract Optional<CompromisedLinkingResource> attackLinkingResource(LinkingResource linking,
            CredentialChange change, EObject source);

    private Collection<CompromisedLinkingResource> filterExsiting(final Collection<CompromisedLinkingResource> linkings,
            final CredentialChange change) {
        //TODO adapt
        return null;
        //return linkings.stream().filter(linking -> !contains(linking, change)).collect(Collectors.toList());
    }

    /*private boolean contains(final CompromisedLinkingResource linking, final CredentialChange change) {
        return change.getCompromisedlinkingresource().stream().anyMatch(referenceLinking -> EcoreUtil
                .equals(referenceLinking.getAffectedElement(), linking.getAffectedElement()));
    }

    private boolean contains(final CompromisedLinkingResource linking, final CredentialChange change) {
        return change.getCompromisedlinkingresource().stream().anyMatch(referenceLinking -> EcoreUtil
                .equals(referenceLinking.getAffectedElement(), linking.getAffectedElement()));
    }TODO remove */
}
