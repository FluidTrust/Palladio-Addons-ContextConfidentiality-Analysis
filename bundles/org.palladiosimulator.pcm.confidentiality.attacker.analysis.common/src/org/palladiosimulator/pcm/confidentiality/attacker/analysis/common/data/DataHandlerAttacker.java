package org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data;

import java.util.Collection;
import java.util.Objects;
import java.util.stream.Collectors;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.Attacker;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.CompromisedData;

public class DataHandlerAttacker {
    private Attacker attacker;

    public DataHandlerAttacker(Attacker attacker) {
        Objects.requireNonNull(attacker);
        this.attacker = attacker;
    }

    public void addData(Collection<CompromisedData> data) {
        var newData = data.stream().filter(referenceData -> !contains(referenceData)).collect(Collectors.toList());
        attacker.getCompromiseddata().addAll(newData);

    }

    private boolean contains(CompromisedData referenceData) {
        return attacker.getCompromiseddata().stream()
                .anyMatch(data -> Objects.equals(data.getReferenceName(), referenceData.getReferenceName())
                        && EcoreUtil.equals(data.getSource(), referenceData.getSource())
                        && EcoreUtil.equals(data.getDataType(), referenceData.getDataType()));
    }

}
