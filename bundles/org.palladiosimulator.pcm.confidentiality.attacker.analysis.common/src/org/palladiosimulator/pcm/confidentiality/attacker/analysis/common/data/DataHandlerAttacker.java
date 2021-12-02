package org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data;

import java.util.Collection;
import java.util.Objects;
import java.util.stream.Collectors;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.DatamodelAttacker;

import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.DatamodelContainer;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksFactory;

public class DataHandlerAttacker {
    private final DatamodelContainer datamodel;
    private final CredentialChange change;

    public DataHandlerAttacker(final CredentialChange change) {
        Objects.requireNonNull(change);
        if (change.getDatamodelcontainer() == null) {
            change.setDatamodelcontainer(KAMP4attackModificationmarksFactory.eINSTANCE.createDatamodelContainer());
        }
        this.datamodel = change.getDatamodelcontainer();
        this.change = change;
    }

    public void addData(final Collection<DatamodelAttacker> data) {
        var newData = data.stream().filter(referenceData -> !contains(referenceData))
                .collect(Collectors.toList());
        this.datamodel.getDatamodelattacker().addAll(newData);


        newData.stream().forEach(orgininalData -> {
            final var compromisedData = KAMP4attackModificationmarksFactory.eINSTANCE.createCompromisedData();
            compromisedData.setAffectedElement(orgininalData);
            compromisedData.getCausingElements().add(orgininalData.getSource());
            this.change.getCompromiseddata().add(compromisedData);
        });


    }

    private boolean contains(final DatamodelAttacker referenceData) {
        return this.datamodel.getDatamodelattacker().stream()
                .anyMatch(data -> Objects.equals(data.getReferenceName(), referenceData.getReferenceName())
                        && EcoreUtil.equals(data.getSource(), referenceData.getSource())
                        && EcoreUtil.equals(data.getDataType(), referenceData.getDataType()));
    }

}
