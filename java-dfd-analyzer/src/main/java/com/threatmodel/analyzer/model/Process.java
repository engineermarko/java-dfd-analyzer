package com.threatmodel.analyzer.model;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Represents a process or functionality in the system
 */
public class Process {
    private String id;
    private String name;
    private String description;
    private String sourceFilePath;
    private List<String> inputDataStructureIds = new ArrayList<>();
    private List<String> outputDataStructureIds = new ArrayList<>();
    private Map<String, Object> metadata = new HashMap<>();
    
    public Process(String id, String name) {
        this.id = id;
        this.name = name;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
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

    public List<String> getInputDataStructureIds() {
        return inputDataStructureIds;
    }

    public void addInputDataStructureId(String dataStructureId) {
        if (!inputDataStructureIds.contains(dataStructureId)) {
            this.inputDataStructureIds.add(dataStructureId);
        }
    }

    public List<String> getOutputDataStructureIds() {
        return outputDataStructureIds;
    }

    public void addOutputDataStructureId(String dataStructureId) {
        if (!outputDataStructureIds.contains(dataStructureId)) {
            this.outputDataStructureIds.add(dataStructureId);
        }
    }

    public Map<String, Object> getMetadata() {
        return metadata;
    }

    public void addMetadata(String key, Object value) {
        this.metadata.put(key, value);
    }
}
