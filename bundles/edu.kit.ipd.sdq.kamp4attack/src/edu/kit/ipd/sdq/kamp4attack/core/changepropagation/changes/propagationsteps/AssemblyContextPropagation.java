package edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.propagationsteps;

import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

public interface AssemblyContextPropagation {
    void calculateAssemblyContextToContextPropagation(CredentialChange changes);

    void calculateAssemblyContextToRemoteResourcePropagation(CredentialChange changes);
    
    void calculateAssemblyContextToLocalResourcePropagation(CredentialChange changes);

    void calculateAssemblyContextToAssemblyContextPropagation(CredentialChange changes);
    
    void calculateAssemblyContextToLinkingResourcePropagation(CredentialChange changes);

}
