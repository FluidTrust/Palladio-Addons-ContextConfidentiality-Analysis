package edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.propagationsteps;

/**
 * Interface for attacker propagation from a compromised linking resource
 *
 * @author majuwa
 *
 */
public interface LinkingPropagation {

    void calculateLinkingResourceToContextPropagation();

    void calculateLinkingResourceToResourcePropagation();

    void calculateLinkingResourceToAssemblyContextPropagation();

}