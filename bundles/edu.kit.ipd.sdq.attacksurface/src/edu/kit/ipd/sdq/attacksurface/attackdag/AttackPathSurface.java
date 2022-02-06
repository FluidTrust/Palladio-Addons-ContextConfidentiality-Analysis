package edu.kit.ipd.sdq.attacksurface.attackdag;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

public class AttackPathSurface implements Iterable<AttackStatusDescriptorNodeContent> {
    private final List<Node<AttackStatusDescriptorNodeContent>> path;
    
    public AttackPathSurface() {
        this.path = new LinkedList<>();
    }
    
    public AttackPathSurface(final List<Node<AttackStatusDescriptorNodeContent>> path) {
        this.path = path;
    }

    public List<AttackStatusDescriptorNodeContent> getPath() {
        return Collections.unmodifiableList(this.path.stream().map(Node::getContent).collect(Collectors.toList()));
    }
    
    @Override
    public int hashCode() {
        //TODO
        return Objects.hash(this.path);
    }
    
    @Override
    public boolean equals(Object other) { //TODO
        if (this == other) {
            return true;
        }
        
        if (other instanceof AttackPathSurface) {
            final var otherPath = (AttackPathSurface) other;
            final int size = size();
            if (size != otherPath.size()) {
                return false;
            }
            
            if (size > 1) {
                if (get(0).isAttackSourceOf(get(1)) != otherPath.get(0).isAttackSourceOf(otherPath.get(1))) {
                    return false;
                }
            }
            
            for (int i = 0; i < size; i++) {
                final var elementOne = get(i);
                final var elementTwo = otherPath.get(i);
                
                if (!elementOne.equals(elementTwo)) {
                    return false;
                }
                
                if (elementOne.isCompromised() != elementTwo.isCompromised()) {
                    return false;
                }
            }
            return true;
        }
        return false;
    }

    public AttackStatusDescriptorNodeContent get(final int index) {
        return getNode(index).getContent();
    }
    
    public Node<AttackStatusDescriptorNodeContent> getNode(final int index) {
        return this.path.get(index);
    }

    public int size() {
        return this.path.size();
    }
    
    public void addFirst(final Node<AttackStatusDescriptorNodeContent> node) {
        this.path.add(0, node);
    }

    public void add(final Node<AttackStatusDescriptorNodeContent> node) {
        this.path.add(node);
    }

    public boolean isEmpty() {
        return this.path.isEmpty();
    }
    
    public AttackPathSurface getUnmodifiableCopy() {
        return new AttackPathSurface(Collections.unmodifiableList(this.path));
    }

    @Override
    public Iterator<AttackStatusDescriptorNodeContent> iterator() {
        return this.path.stream().map(Node::getContent).iterator();
    }
}
