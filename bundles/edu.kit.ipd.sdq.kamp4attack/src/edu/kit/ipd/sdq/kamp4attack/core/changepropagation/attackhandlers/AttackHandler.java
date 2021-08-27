package edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

import org.eclipse.emf.ecore.EObject;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data.DataHandlerAttacker;
import org.palladiosimulator.pcm.confidentiality.attacker.helper.VulnerabilityHelper;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.Attack;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.AttackVector;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.Vulnerability;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.RoleSystemIntegration;
import org.palladiosimulator.pcm.confidentiality.context.helper.PolicyHelper;
import org.palladiosimulator.pcm.confidentiality.context.system.UsageSpecification;
import org.palladiosimulator.pcm.confidentiality.context.xacml.pdp.result.DecisionType;
import org.palladiosimulator.pcm.confidentiality.context.xacml.pdp.result.PDPResult;
import org.palladiosimulator.pcm.core.entity.Entity;

import edu.kit.ipd.sdq.kamp4attack.core.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.core.CompromisedElementHelper;
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

    protected final List<UsageSpecification> getCredentials(final CredentialChange changes) {
        return changes.getContextchange().stream().map(ContextChange::getAffectedElement).collect(Collectors.toList());
    }

//    protected final ContextSet createContextSet(final List<ContextAttribute> contexts) {
//        final var set = SetFactory.eINSTANCE.createContextSet();
//        set.getContexts().addAll(contexts);
//        return set;
//    }

    // TODO: Think about better location
    protected List<Attack> getAttacks() {
        final var listAttackers = this.modelStorage.getModificationMarkRepository().getSeedModifications()
                .getAttackcomponent();
        return listAttackers.stream().flatMap(e -> e.getAffectedElement().getAttacks().stream())
                .collect(Collectors.toList());
    }

    protected List<EObject> createSource(final EObject sourceItem,
            final List<? extends UsageSpecification> contextSet) {
        final List<EObject> list = new ArrayList<>();
        list.add(sourceItem);
        list.addAll(contextSet);
        return list;

    }

    protected Optional<PDPResult> queryAccessForEntity(final Entity target,
            final List<? extends UsageSpecification> credentials) {
        var listComponent = new LinkedList<>(Arrays.asList(target));
        var listSubject = new ArrayList<UsageSpecification>();
        var listEnvironment = new ArrayList<UsageSpecification>();
        var listResource = new ArrayList<UsageSpecification>();
        var listXML = new ArrayList<UsageSpecification>();

        PolicyHelper.createRequestAttributes(listComponent, credentials, listSubject, listEnvironment, listResource,
                listXML);

        var result = getModelStorage().getEval().evaluate(listSubject, listEnvironment, listResource, new ArrayList<>(),
                listXML);
        return result;
    }

    // TODO: Think about better location
    protected Vulnerability checkVulnerability(final Entity component, final CredentialChange change,
            List<UsageSpecification> credentials, final List<Attack> attacks,
            final List<Vulnerability> vulnerabilityList, AttackVector attackVector) {
        var result = queryAccessForEntity(component, credentials);
        var authenticated = false;
        if (result.isPresent()) {
            authenticated = DecisionType.PERMIT.equals(result.get().getDecision());
        }

        var roleSpecification = VulnerabilityHelper.getRoles(getModelStorage().getVulnerabilitySpecification());

        var roles = roleSpecification.stream().filter(e -> CompromisedElementHelper.isHacked(e.getPcmelement(), change))
                .map(RoleSystemIntegration::getRole).collect(Collectors.toList());

        final var vulnerability = VulnerabilityHelper.checkAttack(authenticated, vulnerabilityList, attacks,
                attackVector, roles);
        return vulnerability;
    }

//    // TODO: Think about better location
//    protected ContextSet addCredentialsLocal(final AttackVector attackVector, ContextSet credentials,
//            final List<ContextSet> policies) {
//        if (attackVector == AttackVector.LOCAL) {
//            credentials = EcoreUtil.copy(credentials);
//            for (final var policy : policies) {
//                credentials.getContexts().addAll(policy.getContexts());
//            }
//        }
//        return credentials;
//    }
}
