package edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.propagationsteps;

/**
 * Interface for attacker propagation from a compromised assembly context
 *
 * @author majuwa
 *
 */
public interface AssemblyContextPropagation {
    void calculateAssemblyContextToContextPropagation();

    void calculateAssemblyContextToRemoteResourcePropagation();

    void calculateAssemblyContextToLocalResourcePropagation();

    void calculateAssemblyContextToAssemblyContextPropagation();

    void calculateAssemblyContextToLinkingResourcePropagation();

    void calculateAssemblyContextToGlobalAssemblyContextPropagation();

}
