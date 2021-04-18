package edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.propagationsteps;

import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

public interface LinkingPropagation {

    void calculateLinkingResourceToContextPropagation(CredentialChange changes);

    void calculateLinkingResourceToResourcePropagation(CredentialChange changes);

    void calculateLinkingResourceToAssemblyContextPropagation(CredentialChange changes);

}