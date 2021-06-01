package edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import org.eclipse.emf.ecore.EObject;
import org.eclipse.emf.ecore.util.EcoreUtil;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data.DataHandlerAttacker;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.Attack;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.AttackVector;
import org.palladiosimulator.pcm.confidentiality.context.model.ContextAttribute;
import org.palladiosimulator.pcm.confidentiality.context.set.ContextSet;
import org.palladiosimulator.pcm.confidentiality.context.set.SetFactory;

import edu.kit.ipd.sdq.kamp4attack.core.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.ContextChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

public abstract class AttackHandler {
    private final BlackboardWrapper modelStorage;
    private final DataHandlerAttacker dataHandler;

    public AttackHandler(final BlackboardWrapper modelStorage, final DataHandlerAttacker dataHandler) {
        Objects.requireNonNull(modelStorage);
        Objects.requireNonNull(dataHandler);
        this.modelStorage = modelStorage;
        this.dataHandler = dataHandler;

    }

    protected BlackboardWrapper getModelStorage() {
        return this.modelStorage;
    }

    protected DataHandlerAttacker getDataHandler() {
        return this.dataHandler;
    }

    protected final ContextSet getCredentials(final CredentialChange changes) {
        final var contexts = changes.getContextchange().stream().map(ContextChange::getAffectedElement)
                .collect(Collectors.toList());
        return this.createContextSet(contexts);
    }

    protected final ContextSet createContextSet(final List<ContextAttribute> contexts) {
        final var set = SetFactory.eINSTANCE.createContextSet();
        set.getContexts().addAll(contexts);
        return set;
    }

    // TODO: Think about better location
    protected List<Attack> getAttacks() {
        final var listAttackers = this.modelStorage.getModificationMarkRepository().getSeedModifications()
                .getAttackcomponent();
        return listAttackers.stream().flatMap(e -> e.getAffectedElement().getAttacks().stream())
                .collect(Collectors.toList());
    }

    protected List<EObject> createSource(final EObject sourceItem, final ContextSet contextSet) {
        final List<EObject> list = new ArrayList<>();
        list.add(sourceItem);
        list.addAll(contextSet.getContexts());
        return list;

    }

    // TODO: Think about better location
    protected ContextSet addCredentialsLocal(final AttackVector attackVector, ContextSet credentials,
            final List<ContextSet> policies) {
        if (attackVector == AttackVector.LOCAL) {
            credentials = EcoreUtil.copy(credentials);
            for (final var policy : policies) {
                credentials.getContexts().addAll(policy.getContexts());
            }
        }
        return credentials;
    }
}
