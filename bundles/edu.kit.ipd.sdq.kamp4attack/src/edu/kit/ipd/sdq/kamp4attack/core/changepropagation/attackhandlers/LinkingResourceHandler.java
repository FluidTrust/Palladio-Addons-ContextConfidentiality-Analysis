package edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers;

import java.util.Collection;
import java.util.Optional;
import java.util.stream.Collectors;

import org.eclipse.emf.ecore.EObject;
import org.eclipse.emf.ecore.util.EcoreUtil;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data.DataHandlerAttacker;
import org.palladiosimulator.pcm.resourceenvironment.LinkingResource;

import edu.kit.ipd.sdq.kamp4attack.core.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedLinkingResource;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

public abstract class LinkingResourceHandler extends AttackHandler {

    protected LinkingResourceHandler(BlackboardWrapper modelStorage, DataHandlerAttacker dataHandler) {
        super(modelStorage, dataHandler);
    }
    
    public void attackLinkingResource(Collection<LinkingResource> linking, CredentialChange change,
            EObject source) {
        var compromisedResources = linking.stream().map(e -> this.attackLinkingResource(e, change, source))
                .flatMap(Optional::stream).collect(Collectors.toList());
        var newCompromisedResources = filterExsiting(compromisedResources, change);
        if (!newCompromisedResources.isEmpty()) {
            handleDataExtraction(newCompromisedResources);
            change.setChanged(true);
            change.getCompromisedlinkingresource().addAll(newCompromisedResources);
        }
    }

    private void handleDataExtraction(Collection<CompromisedLinkingResource> linking) {
        //extension possible
    }

    protected abstract Optional<CompromisedLinkingResource> attackLinkingResource(LinkingResource linking,
            CredentialChange change, EObject source);

    private Collection<CompromisedLinkingResource> filterExsiting(Collection<CompromisedLinkingResource> linkings,
            CredentialChange change) {
        return linkings.stream().filter(linking -> !contains(linking, change)).collect(Collectors.toList());

    }

    private boolean contains(CompromisedLinkingResource linking, CredentialChange change) {
        return change.getCompromisedlinkingresource().stream().anyMatch(referenceLinking -> EcoreUtil
                .equals(referenceLinking.getAffectedElement(), linking.getAffectedElement()));
    }
}
