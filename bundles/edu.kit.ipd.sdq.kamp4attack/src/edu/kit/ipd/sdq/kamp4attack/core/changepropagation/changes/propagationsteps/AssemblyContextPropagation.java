package edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.propagationsteps;

import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

/**
 * Interface for attacker propagation from a compromised assembly context
 *
 * @author majuwa
 *
 */
public interface AssemblyContextPropagation {
    void calculateAssemblyContextToContextPropagation(CredentialChange changes);

    void calculateAssemblyContextToRemoteResourcePropagation(CredentialChange changes);

    void calculateAssemblyContextToLocalResourcePropagation(CredentialChange changes);

    void calculateAssemblyContextToAssemblyContextPropagation(CredentialChange changes);

    void calculateAssemblyContextToLinkingResourcePropagation(CredentialChange changes);

    void calculateAssemblyContextToGlobalAssemblyContextPropagation(CredentialChange changePropagationDueToCredential);

}
