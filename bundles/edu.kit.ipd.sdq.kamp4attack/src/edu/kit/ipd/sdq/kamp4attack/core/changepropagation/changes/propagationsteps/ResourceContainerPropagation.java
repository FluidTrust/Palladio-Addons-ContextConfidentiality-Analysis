package edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.propagationsteps;

import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

/**
 * Interface for attacker propagation from a compromised resource container
 *
 * @author majuwa
 *
 */
public interface ResourceContainerPropagation {

    void calculateResourceContainerToContextPropagation(CredentialChange changes);

    void calculateResourceContainerToRemoteAssemblyContextPropagation(CredentialChange changes);

    void calculateResourceContainerToLocalAssemblyContextPropagation(CredentialChange changes);

    void calculateResourceContainerToResourcePropagation(CredentialChange changes);

    void calculateResourceContainerToLinkingResourcePropagation(CredentialChange changes);

}
