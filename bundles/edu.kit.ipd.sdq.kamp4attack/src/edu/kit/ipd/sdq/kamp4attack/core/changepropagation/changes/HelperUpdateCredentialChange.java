package edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes;

import java.util.Collection;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.eclipse.emf.ecore.EObject;
import org.eclipse.emf.ecore.util.EcoreUtil;
import org.palladiosimulator.pcm.confidentiality.context.system.UsageSpecification;

import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.ContextChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksFactory;

public class HelperUpdateCredentialChange {

    private HelperUpdateCredentialChange() {

    }

    public static void updateCredentials(final CredentialChange changes,
            final Stream<ContextChange> streamContextChange) {
        final var listChanges = streamContextChange
                .filter(e -> changes.getContextchange().stream()
                        .noneMatch(f -> EcoreUtil.equals(f.getAffectedElement(), e.getAffectedElement())))
                .collect(Collectors.toList());

        changes.getContextchange().addAll(listChanges);

        if (!listChanges.isEmpty()) {
            changes.setChanged(true);
        }
    }

    public static ContextChange createContextChange(final UsageSpecification e,
            final Collection<? extends EObject> sources) {
        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createContextChange();
        change.setToolderived(true);
        change.setAffectedElement(e);
        if (sources != null && !sources.isEmpty()) {
            change.getCausingElements().addAll(sources);
        }
        return change;
    }

}
