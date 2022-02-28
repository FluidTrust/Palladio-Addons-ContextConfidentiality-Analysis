package edu.kit.ipd.sdq.attacksurface.graph;

import java.util.Arrays;
import java.util.Objects;

import com.google.common.graph.EndpointPair;

public class AttackStatusEdge {
    private final AttackStatusEdgeContent content;
    private final EndpointPair<AttackStatusNodeContent> nodes;
    
    public AttackStatusEdge(final AttackStatusEdgeContent content, final EndpointPair<AttackStatusNodeContent> nodes) {
        this.content = content;
        this.nodes = nodes;
    }

    public AttackStatusEdgeContent getContent() {
        return content;
    }

    public EndpointPair<AttackStatusNodeContent> getNodes() {
        return nodes;
    }
    
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
        return "AttackStatusEdge [content=" + content.getCauseIds() + ", " + 
                nodes.source().getContainedElement().getEntityName() + " -> " +
                nodes.target().getContainedElement().getEntityName() + "]";
    }

    public AttackPathSurface toPath() {
        return new AttackPathSurface(Arrays.asList(this));
    }
}
