package edu.kit.kastel.sdq.kamp4attack.graph.api;

import java.nio.file.Path;
import java.util.Optional;

import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.AbstractKAMP4attackModificationRepository;

public interface AttackGraphCreation {

    Optional<Path> createAttackGraph(AbstractKAMP4attackModificationRepository<?> modificationMark);

}
