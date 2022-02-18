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
    private List<String> data;

    public AttackerComponentPathDTO(KAMP4attackModificationRepository repository) {
        this.data = new ArrayList<>();
//        this.startComponent = repository.getSeedModifications().getAttackcomponent().get(0).get

        setAttackComplexity(repository);
        setStartComponent(repository);
        setData(repository);
    }

    private void setStartComponent(KAMP4attackModificationRepository repository) {
        if (repository.getSeedModifications().getAttackcomponent().size() != 1) {
            throw new IllegalStateException("Unsupported Number of attackers");
        }

        var attacker = repository.getSeedModifications().getAttackcomponent().get(0).getAffectedElement();
        if (attacker == null) {
            throw new IllegalStateException("Attacker is null");
        }

        if (attacker.getCompromisedComponents().size() != 1 || !attacker.getCompromisedLinkingResources().isEmpty()
                || !attacker.getCompromisedResources().isEmpty()) {
            throw new IllegalStateException("Unsupported number of starting points");
        }
        var component = attacker.getCompromisedComponents().get(0);
        this.startComponent = component.getEntityName();
        this.attackername = attacker.getEntityName();
    }

    private void setAttackComplexity(KAMP4attackModificationRepository repository) {
        if (repository.getChangePropagationSteps().size() != 1) {
            throw new IllegalStateException("Unsupported number of changes");
        }



        var setSources = new HashSet<EObject>();

        var credentialChange = repository.getChangePropagationSteps().get(0);

        credentialChange.getCompromisedassembly().stream().flatMap(e -> e.getCausingElements().stream())
                .forEach(setSources::add);
        credentialChange.getCompromisedlinkingresource().stream().flatMap(e -> e.getCausingElements().stream())
                .forEach(setSources::add);
        credentialChange.getCompromisedresource().stream().flatMap(e -> e.getCausingElements().stream())
                .forEach(setSources::add);
        credentialChange.getCompromisedservice().stream().flatMap(e -> e.getCausingElements().stream())
                .forEach(setSources::add);

        var highComplexity = setSources.stream().filter(Vulnerability.class::isInstance).map(Vulnerability.class::cast)
                .anyMatch(e -> e.getAttackComplexity() == AttackComplexity.HIGH);

        this.attackComplexity = highComplexity ? AttackComplexity.LOW.toString() : AttackComplexity.HIGH.toString();

    }

    private void setData(KAMP4attackModificationRepository repository) {
        if (repository.getChangePropagationSteps().size() != 1) {
            throw new IllegalStateException("Unsupported number of changes");
        }

        var credentialChange = repository.getChangePropagationSteps().get(0);

        credentialChange.getCompromiseddata().stream().map(CompromisedData::getAffectedElement).map(data -> {

            var sourceName = data.getSource().getEntityName();
            var sourceID = data.getSource().getId();
            var variableName = data.getReferenceName() == null ? data.getMethod().getEntityName()
                    : data.getReferenceName();
            return String.format("%s:%s:%s", sourceName, sourceID, variableName);

        }).forEach(this.data::add);

    }

}
