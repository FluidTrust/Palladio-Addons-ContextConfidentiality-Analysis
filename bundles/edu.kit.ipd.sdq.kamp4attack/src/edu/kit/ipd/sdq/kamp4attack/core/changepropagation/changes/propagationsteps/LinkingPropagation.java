package edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.propagationsteps;

import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

/**
 * Interface for attacker propagation from a compromised linking resource
 *
 * @author majuwa
 *
 */
public interface LinkingPropagation {

    void calculateLinkingResourceToContextPropagation(CredentialChange changes);

    void calculateLinkingResourceToResourcePropagation(CredentialChange changes);

    void calculateLinkingResourceToAssemblyContextPropagation(CredentialChange changes);

}