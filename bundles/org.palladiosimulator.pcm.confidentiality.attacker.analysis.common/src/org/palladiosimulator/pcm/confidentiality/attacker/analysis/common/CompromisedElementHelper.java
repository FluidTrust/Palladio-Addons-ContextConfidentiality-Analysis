package org.palladiosimulator.pcm.confidentiality.attacker.analysis.common;

import java.util.ArrayList;
import java.util.List;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.core.entity.Entity;
import org.palladiosimulator.pcm.resourceenvironment.LinkingResource;
import org.palladiosimulator.pcm.resourceenvironment.ResourceContainer;

import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedAssembly;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedLinkingResource;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedResource;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedService;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

/**
 * Helper class for identifying already compromised system elements
 *
 * @author majuwa
 *
 */
public class CompromisedElementHelper {

    private CompromisedElementHelper() {
        // intentional
    }

    public static List<Entity> getHacked(CredentialChange change) {
        var list = new ArrayList<Entity>();
        change.getCompromisedassembly().stream().map(CompromisedAssembly::getAffectedElement).forEach(list::add);
        change.getCompromisedlinkingresource().stream().map(CompromisedLinkingResource::getAffectedElement)
                .forEach(list::add);
        change.getCompromisedresource().stream().map(CompromisedResource::getAffectedElement).forEach(list::add);
        change.getCompromisedservice().stream().map(CompromisedService::getAffectedElement).forEach(list::add);
        return list;
    }

//    public static boolean isHacked(final PCMElement element, final CredentialChange change) {
//
//        return isHacked(element.getAssemblycontext(), change) && isHacked(element.getLinkingresource(), change)
//                && isHacked(element.getResourcecontainer(), change);
//
//    }

    public static boolean isHacked(final AssemblyContext component, final CredentialChange change) {
        return change.getCompromisedassembly().stream().map(CompromisedAssembly::getAffectedElement)
                .anyMatch(e -> EcoreUtil.equals(component, e));
    }

    public static boolean isHacked(final ResourceContainer container, final CredentialChange change) {
        return change.getCompromisedresource().stream().map(CompromisedResource::getAffectedElement)
                .anyMatch(e -> EcoreUtil.equals(container, e));
    }

    public static boolean isHacked(final LinkingResource container, final CredentialChange change) {
        return change.getCompromisedlinkingresource().stream().map(CompromisedLinkingResource::getAffectedElement)
                .anyMatch(e -> EcoreUtil.equals(container, e));
    }

}
