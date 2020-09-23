package edu.kit.ipd.sdq.kamp4attack.core.changepropagation;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.palladiosimulator.pcm.confidentiality.context.model.ContextAttribute;
import org.palladiosimulator.pcm.confidentiality.context.set.ContextSet;
import org.palladiosimulator.pcm.confidentiality.context.set.SetFactory;
import org.palladiosimulator.pcm.confidentiality.context.specification.assembly.AttributeProvider;
import org.palladiosimulator.pcm.confidentiality.context.specification.assembly.SystemPolicySpecification;

import edu.kit.ipd.sdq.kamp4attack.core.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksFactory;

public abstract class Change<T> {

    protected Collection<T> initialMarkedItems;

    protected BlackboardWrapper modelStorage;

    public Change(BlackboardWrapper v) {
        modelStorage = v;
        initialMarkedItems = loadInitialMarkedItems();
    }

    protected abstract Collection<T> loadInitialMarkedItems();

    protected final Stream<SystemPolicySpecification> getPolicyStream() {
        return modelStorage.getSpecification().getPolicyspecification().stream()
                .filter(SystemPolicySpecification.class::isInstance).map(SystemPolicySpecification.class::cast);
    }

    protected void updateFromContextProviderStream(CredentialChange changes,
            Stream<AttributeProvider> streamAttributeProvider) {
        var streamContextChange = streamAttributeProvider.flatMap(e -> e.getContextset().getContexts().stream())
                .map(e -> {
                    var change = KAMP4attackModificationmarksFactory.eINSTANCE.createContextChange();
                    change.setToolderived(true);
                    change.setAffectedElement(e);
                    return change;
                });

        var listChanges = streamContextChange
                .filter(e -> changes.getContextchange().stream()
                        .noneMatch(f -> EcoreUtil.equals(f.getAffectedElement(), e.getAffectedElement())))
                .collect(Collectors.toList());

        changes.getContextchange().addAll(listChanges);

        if (!listChanges.isEmpty()) {
            changes.setChanged(true);
        }
    }

    protected final ContextSet createContextSet(List<ContextAttribute> contexts) {
        var set = SetFactory.eINSTANCE.createContextSet();
        set.getContexts().addAll(contexts);
        return set;
    }
}
