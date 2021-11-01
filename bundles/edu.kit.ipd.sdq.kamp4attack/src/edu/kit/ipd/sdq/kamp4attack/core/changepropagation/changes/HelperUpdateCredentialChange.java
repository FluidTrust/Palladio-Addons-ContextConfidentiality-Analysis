package edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes;

import java.util.Collection;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.eclipse.emf.ecore.EObject;
import org.eclipse.emf.ecore.util.EcoreUtil;
import org.palladiosimulator.pcm.confidentiality.context.system.UsageSpecification;

import edu.kit.ipd.sdq.kamp4attack.core.CachePDP;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.ContextChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksFactory;

/**
 * Helper class for updating the result object
 *
 * @author majuwa
 *
 */
public class HelperUpdateCredentialChange {

    private HelperUpdateCredentialChange() {
        // intentional
    }

    /**
     * Updates the list of stolen credentials based on the stream of newly compromised credentials.
     * The newly compromised streams is filtered with already compromised credentials, that no
     * duplicates can exist
     *
     * @param changes
     *            compromised elements
     * @param streamContextChange
     *            newly compromised credentials
     */
    public static void updateCredentials(final CredentialChange changes,
            final Stream<ContextChange> streamContextChange) {
        final var listChanges = streamContextChange
                .filter(e -> changes.getContextchange().stream()
                        .noneMatch(f -> equalUsageElement(f,e)
                                ))
                .collect(Collectors.toList());

        changes.getContextchange().addAll(listChanges);

        if (!listChanges.isEmpty()) {
            CachePDP.instance().clearCache();
            changes.setChanged(true);
        }
    }

    private static boolean equalUsageElement(ContextChange changeReference, ContextChange toCompare) {
        var referenceCredential = changeReference.getAffectedElement();
        var newCredential = toCompare.getAffectedElement();

        var attributesEquals = EcoreUtil.equals(referenceCredential.getAttribute(), newCredential.getAttribute());
        var valueEquals = EcoreUtil.equals(referenceCredential.getAttributevalue(),
                newCredential.getAttributevalue());

        return attributesEquals && valueEquals;
    }

    /**
     * Creates a new {@link ContextChange} object. It is used for storing compromised credentials in
     * the output result
     *
     * @param usageSpecification
     *            compromised credential
     * @param sources
     *            collection of objects from whom the credential was stolen
     * @return new {@link ContextChange}
     */
    public static ContextChange createContextChange(final UsageSpecification usageSpecification,
            final Collection<? extends EObject> sources) {
        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createContextChange();
        change.setToolderived(true);
        change.setAffectedElement(usageSpecification);
        if (sources != null && !sources.isEmpty()) {
            change.getCausingElements().addAll(sources);
        }
        return change;
    }

}
