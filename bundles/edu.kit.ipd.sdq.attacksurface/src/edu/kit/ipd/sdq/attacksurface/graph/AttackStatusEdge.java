package edu.kit.ipd.sdq.attacksurface.graph;

import java.util.Arrays;
import java.util.Iterator;
import java.util.Objects;
import java.util.stream.Collectors;

import com.google.common.graph.EndpointPair;

import de.uka.ipd.sdq.identifier.Identifier;

/**
 * Represents an edge in the attack graph containing the endpoints of the edge and
 * the edge content for storing the attack causes.
 * 
 * @author ugnwq
 * @version 1.0
 */
public class AttackStatusEdge implements Iterable<AttackNodeContent> {
    private final AttackStatusEdgeContent content;
    private final EndpointPair<AttackNodeContent> nodes;
    
    public AttackStatusEdge(final AttackStatusEdgeContent content, final EndpointPair<AttackNodeContent> nodes) {
        this.content = content;
        this.nodes = nodes;
    }

    /**
     * 
     * @return the attack causes edge content
     */
    public AttackStatusEdgeContent getContent() {
        return content;
    }

    /**
     * 
     * @return the nodes of the edge
     */
    public EndpointPair<AttackNodeContent> getNodes() {
        return nodes;
    }
    
    /**
     * 
     * @return the reversal of the edge
     */
    public AttackStatusEdge createReverseEdge() {
        return new AttackStatusEdge(this.content, EndpointPair.ordered(this.nodes.target(), this.nodes.source()));
    }

    @Override
    public int hashCode() {
        return Objects.hash(content, nodes);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        AttackStatusEdge other = (AttackStatusEdge) obj;
        return Objects.equals(content, other.content) && Objects.equals(nodes, other.nodes);
    }

    @Override
    public String toString() {
        return "AttackStatusEdge [content=" + content.getCauses().stream()
                    .map(Identifier::getId).collect(Collectors.toSet()) + ", " + 
                nodes.source().getContainedElement().getEntityName() + " -> " +
                nodes.target().getContainedElement().getEntityName() + "]";
    }

    /**
     * 
     * @return the path containing only this edge
     */
    public AttackPathSurface toPath() {
        return new AttackPathSurface(Arrays.asList(this));
    }

    @Override
    public Iterator<AttackNodeContent> iterator() {
        return getNodes().iterator();
    }
}
