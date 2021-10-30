package org.palladiosimulator.pcm.confidentiality.attacker.analysis.common;

import java.util.Collection;

import org.eclipse.emf.ecore.EObject;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.ServiceRestriction;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.resourceenvironment.LinkingResource;
import org.palladiosimulator.pcm.resourceenvironment.ResourceContainer;

import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedAssembly;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedLinkingResource;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedResource;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedService;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksFactory;

/**
 * Helper class for creating compromised system elements in the result.
 *
 * @author majuwa
 *
 */
public class HelperCreationCompromisedElements {
    private HelperCreationCompromisedElements() {

    }

    public static CompromisedResource createCompromisedResource(final ResourceContainer container,
            final Collection<? extends EObject> list) {
        final var compromisedResource = KAMP4attackModificationmarksFactory.eINSTANCE.createCompromisedResource();
        compromisedResource.setToolderived(true);
        compromisedResource.setAffectedElement(container);
        compromisedResource.getCausingElements().addAll(list);
        return compromisedResource;
    }

    public static CompromisedAssembly createCompromisedAssembly(final AssemblyContext container,
            final Collection<? extends EObject> list) {
        final var compromisedResource = KAMP4attackModificationmarksFactory.eINSTANCE.createCompromisedAssembly();
        compromisedResource.setToolderived(true);
        compromisedResource.setAffectedElement(container);
        compromisedResource.getCausingElements().addAll(list);
        return compromisedResource;
    }

    public static CompromisedLinkingResource createCompromisedLinking(final LinkingResource linking,
            final Collection<? extends EObject> list) {
        final var compromisedResource = KAMP4attackModificationmarksFactory.eINSTANCE
                .createCompromisedLinkingResource();
        compromisedResource.setToolderived(true);
        compromisedResource.setAffectedElement(linking);
        compromisedResource.getCausingElements().addAll(list);
        return compromisedResource;
    }

    public static CompromisedService createCompromisedService(final ServiceRestriction service,
            final Collection<? extends EObject> list) {
        final var compromisedService = KAMP4attackModificationmarksFactory.eINSTANCE
                .createCompromisedService();
        compromisedService.setToolderived(true);
        compromisedService.setAffectedElement(service);
        compromisedService.getCausingElements().addAll(list);
        return compromisedService;
    }
}
