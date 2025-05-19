package com.threatmodel.analyzer.model;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Represents a data structure in the Java project (like a class or interface with data)
 */
public class DataStructure {
    private String name;
    private String fullyQualifiedName;
    private String description;
    private String sourceFilePath;
    private List<DataField> fields = new ArrayList<>();
    private Map<String, String> annotations = new HashMap<>();
    private DataStructureType type;
    private boolean isExternal;
    
    public enum DataStructureType {
        CLASS,
        INTERFACE,
        ENUM,
        RECORD,
        DTO,
        ENTITY,
        OTHER
    }
    
    public DataStructure(String name, String fullyQualifiedName) {
        this.name = name;
        this.fullyQualifiedName = fullyQualifiedName;
        this.type = DataStructureType.OTHER;
        this.isExternal = false;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getFullyQualifiedName() {
        return fullyQualifiedName;
    }

    public void setFullyQualifiedName(String fullyQualifiedName) {
        this.fullyQualifiedName = fullyQualifiedName;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getSourceFilePath() {
        return sourceFilePath;
    }

    public void setSourceFilePath(String sourceFilePath) {
        this.sourceFilePath = sourceFilePath;
    }

    public List<DataField> getFields() {
        return fields;
    }

    public void addField(DataField field) {
        this.fields.add(field);
    }

    public Map<String, String> getAnnotations() {
        return annotations;
    }

    public void addAnnotation(String name, String value) {
        this.annotations.put(name, value);
    }

    public DataStructureType getType() {
        return type;
    }

    public void setType(DataStructureType type) {
        this.type = type;
    }

    public boolean isExternal() {
        return isExternal;
    }

    public void setExternal(boolean isExternal) {
        this.isExternal = isExternal;
    }
    
    @Override
    public String toString() {
        return name + " (" + type + ")" + (isExternal ? " [EXTERNAL]" : "");
    }
}
