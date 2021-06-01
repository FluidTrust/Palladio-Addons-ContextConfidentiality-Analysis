package org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data;

import java.util.Collection;
import java.util.Objects;
import java.util.stream.Collectors;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.Attacker;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.CompromisedData;

public class DataHandlerAttacker {
    private final Attacker attacker;

    public DataHandlerAttacker(final Attacker attacker) {
        Objects.requireNonNull(attacker);
        this.attacker = attacker;
    }

    public void addData(final Collection<CompromisedData> data) {
        final var newData = data.stream().filter(referenceData -> !this.contains(referenceData))
                .collect(Collectors.toList());
        this.attacker.getCompromiseddata().addAll(newData);

    }

    private boolean contains(final CompromisedData referenceData) {
        return this.attacker.getCompromiseddata().stream()
                .anyMatch(data -> Objects.equals(data.getReferenceName(), referenceData.getReferenceName())
                        && EcoreUtil.equals(data.getSource(), referenceData.getSource())
                        && EcoreUtil.equals(data.getDataType(), referenceData.getDataType()));
    }

}
