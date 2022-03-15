package edu.kit.ipd.sdq.attacksurface.core.changepropagation.attackhandlers.credentialquerying;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.CredentialSystemIntegration;
import org.palladiosimulator.pcm.confidentiality.context.system.UsageSpecification;
import org.palladiosimulator.pcm.confidentiality.context.xacml.pdp.result.DecisionType;
import org.palladiosimulator.pcm.confidentiality.context.xacml.pdp.result.PDPResult;
import org.palladiosimulator.pcm.core.entity.Entity;
import org.palladiosimulator.pcm.repository.Signature;

import de.uka.ipd.sdq.identifier.Identifier;
import edu.kit.ipd.sdq.attacksurface.graph.PCMElementType;
import edu.kit.ipd.sdq.kamp4attack.core.api.BlackboardWrapper;

/**
 * Represents a querying for credentials using only {@link CredentialSystemIntegration}s for the decision.
 * 
 * @author ugnwq
 * @version 1.0
 */
public class SimpleCredentialQuerying implements CredentialQuerying {
    private final BlackboardWrapper board;
    
    public SimpleCredentialQuerying(final BlackboardWrapper board) {
        this.board = board;
    }
    
    @Override
    public Optional<PDPResult> queryAccessForEntity(Entity target, List<? extends UsageSpecification> credentials,
            Signature signature) { // for considering signature: use PDPCredentialQuerying
        final var credentialIntegrations = getCredentialIntegrations(target);
        if (!credentialIntegrations.isEmpty()) {
            final var credentialIntegrationsIds = toIds(credentialIntegrations);
            if (credentials.containsAll(credentialIntegrations)) {
                return Optional.of(new PDPResult(DecisionType.PERMIT, credentialIntegrationsIds));
            }
            final var notFulfilledCredentials = toIds(credentialIntegrations);
            notFulfilledCredentials.removeAll(toIds(credentials));
            return Optional.of(new PDPResult(DecisionType.DENY, notFulfilledCredentials));
        }
        return Optional.of(new PDPResult(DecisionType.DENY, new ArrayList<>()));
    }

    private List<String> toIds(List<? extends UsageSpecification> credentials) {
        return credentials
                .stream()
                .map(Identifier::getId)
                .collect(Collectors.toList());
    }

    private List<? extends UsageSpecification> getCredentialIntegrations(Entity target) {
        return this.board
                    .getVulnerabilitySpecification()
                    .getVulnerabilities()
                    .stream()
                    .filter(PCMElementType.typeOf(target).getElementEqualityPredicate(target))
                    .filter(CredentialSystemIntegration.class::isInstance)
                    .map(CredentialSystemIntegration.class::cast)
                    .map(CredentialSystemIntegration::getCredential)
                    .collect(Collectors.toList());
    }

    @Override
    public BlackboardWrapper getModelStorage() {
        return this.board;
    }
}
