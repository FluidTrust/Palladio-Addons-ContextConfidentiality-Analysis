package org.palladiosimulator.pcm.confidentiality.attacker.variation.output;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

import org.eclipse.emf.ecore.EObject;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.AttackComplexity;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.Vulnerability;

import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedData;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationRepository;

public class AttackerComponentPathDTO {

    private String attackername;
    private String startComponent;
    private String attackComplexity;
    private final List<String> data;

    public AttackerComponentPathDTO(final KAMP4attackModificationRepository repository) {
        this.data = new ArrayList<>();

        this.setAttackComplexity(repository);
        this.setStartComponent(repository);
        this.setData(repository);
    }

    public final String getAttackername() {
        return this.attackername;
    }

    public final String getStartComponent() {
        return this.startComponent;
    }

    public final String getAttackComplexity() {
        return this.attackComplexity;
    }

    public final List<String> getData() {
        return this.data;
    }

    private void setStartComponent(final KAMP4attackModificationRepository repository) {
        if (repository.getSeedModifications().getAttackcomponent().size() != 1) {
            throw new IllegalStateException("Unsupported Number of attackers");
        }

        final var attacker = repository.getSeedModifications().getAttackcomponent().get(0).getAffectedElement();
        if (attacker == null) {
            throw new IllegalStateException("Attacker is null");
        }

        if (attacker.getCompromisedComponents().size() != 1 || !attacker.getCompromisedLinkingResources().isEmpty()
                || !attacker.getCompromisedResources().isEmpty()) {
            throw new IllegalStateException("Unsupported number of starting points");
        }
        final var component = attacker.getCompromisedComponents().get(0);
        this.startComponent = component.getEntityName();
        this.attackername = attacker.getEntityName();
    }

    private void setAttackComplexity(final KAMP4attackModificationRepository repository) {
        if (repository.getChangePropagationSteps().size() != 1) {
            throw new IllegalStateException("Unsupported number of changes");
        }

        final var setSources = new HashSet<EObject>();

        final var credentialChange = repository.getChangePropagationSteps().get(0);

        credentialChange.getCompromisedassembly().stream().flatMap(e -> e.getCausingElements().stream())
                .forEach(setSources::add);
        credentialChange.getCompromisedlinkingresource().stream().flatMap(e -> e.getCausingElements().stream())
                .forEach(setSources::add);
        credentialChange.getCompromisedresource().stream().flatMap(e -> e.getCausingElements().stream())
                .forEach(setSources::add);
        credentialChange.getCompromisedservice().stream().flatMap(e -> e.getCausingElements().stream())
                .forEach(setSources::add);

        final var highComplexity = setSources.stream().filter(Vulnerability.class::isInstance)
                .map(Vulnerability.class::cast).anyMatch(e -> e.getAttackComplexity() == AttackComplexity.HIGH);

        this.attackComplexity = highComplexity ? AttackComplexity.HIGH.toString() : AttackComplexity.LOW.toString();

    }

    private void setData(final KAMP4attackModificationRepository repository) {
        if (repository.getChangePropagationSteps().size() != 1) {
            throw new IllegalStateException("Unsupported number of changes");
        }

        final var credentialChange = repository.getChangePropagationSteps().get(0);

        credentialChange.getCompromiseddata().stream().map(CompromisedData::getAffectedElement).map(data -> {

            final var sourceName = data.getSource().getEntityName();
            final var sourceID = data.getSource().getId();
            final var methodName = data.getMethod().getEntityName();
            final var variableName = data.getReferenceName() == null ? "RETURN" : data.getReferenceName();
            return String.format("%s:%s:%s:%s", sourceName, sourceID, methodName, variableName);

        }).forEach(this.data::add);

    }

}
