package org.palladiosimulator.pcm.confidentiality.context.analysis.execution.partition;

import de.uka.ipd.sdq.workflow.mdsd.blackboard.ResourceSetPartition;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationRepository;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksPackage;

public class ModificationMarkPartition extends ResourceSetPartition {
    public KAMP4attackModificationRepository getModificationRepository() {
        return (KAMP4attackModificationRepository) this
            .getElement(KAMP4attackModificationmarksPackage.eINSTANCE.getKAMP4attackModificationRepository())
            .get(0);
    }
}
