package com.threatmodel.analyzer.model;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Represents the complete analysis result of a Java project
 */
public class AnalysisResult {
    private List<DataStructure> dataStructures = new ArrayList<>();
    private List<DataFlow> dataFlows = new ArrayList<>();
    private List<ExternalEntity> externalEntities = new ArrayList<>();
    private List<Process> processes = new ArrayList<>();
    private List<DataStore> dataStores = new ArrayList<>();
    
    // Project metadata
    private String projectName;
    private String projectDescription;
    private Map<String, String> projectMetadata = new HashMap<>();

    public List<DataStructure> getDataStructures() {
        return dataStructures;
    }

    public void addDataStructure(DataStructure dataStructure) {
        this.dataStructures.add(dataStructure);
    }

    public List<DataFlow> getDataFlows() {
        return dataFlows;
    }

    public void addDataFlow(DataFlow dataFlow) {
        this.dataFlows.add(dataFlow);
    }

    public List<ExternalEntity> getExternalEntities() {
        return externalEntities;
    }

    public void addExternalEntity(ExternalEntity externalEntity) {
        this.externalEntities.add(externalEntity);
    }

    public List<Process> getProcesses() {
        return processes;
    }

    public void addProcess(Process process) {
        this.processes.add(process);
    }

    public List<DataStore> getDataStores() {
        return dataStores;
    }

    public void addDataStore(DataStore dataStore) {
        this.dataStores.add(dataStore);
    }

    public String getProjectName() {
        return projectName;
    }

    public void setProjectName(String projectName) {
        this.projectName = projectName;
    }

    public String getProjectDescription() {
        return projectDescription;
    }

    public void setProjectDescription(String projectDescription) {
        this.projectDescription = projectDescription;
    }

    public Map<String, String> getProjectMetadata() {
        return projectMetadata;
    }

    public void addProjectMetadata(String key, String value) {
        this.projectMetadata.put(key, value);
    }
    
    /**
     * Gets a summary of the analysis results
     */
    public String getSummary() {
        StringBuilder summary = new StringBuilder();
        summary.append("Project Analysis Summary for ").append(projectName).append("\n");
        summary.append("================================\n\n");
        
        summary.append("Data Structures: ").append(dataStructures.size()).append("\n");
        summary.append("Data Flows: ").append(dataFlows.size()).append("\n");
        summary.append("External Entities: ").append(externalEntities.size()).append("\n");
        summary.append("Processes: ").append(processes.size()).append("\n");
        summary.append("Data Stores: ").append(dataStores.size()).append("\n\n");
        
        return summary.toString();
    }
}
