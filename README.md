# Java DFD Analyzer

A Linux application for automatically generating Data Flow Diagrams (DFDs) from Java projects to support threat modeling.

## Overview

The Java DFD Analyzer parses a Java repository to automatically extract information about data structures, data flows, external entities, and data stores. This information is used to generate a comprehensive Data Flow Diagram that can be used as the foundation for threat modeling.

The tool analyzes Java code to identify:

1. **Data Structures**: Classes, interfaces, DTOs, entities, etc. with their fields and properties
2. **External Inputs/Outputs**: External systems, APIs, user interfaces, etc. that interact with the application
3. **Internal Processes**: Methods and functions that transform or process data
4. **Data Stores**: Databases, caches, file systems, etc. where data is persistently stored
5. **Data Flows**: The movement of data between components

## Features

- **Automatic Code Analysis**: Uses JavaParser to analyze Java source code
- **Data Structure Detection**: Identifies classes, interfaces, and their fields
- **External Entity Detection**: Identifies external systems, APIs, and interfaces
- **Process Detection**: Identifies methods that transform data
- **Data Store Detection**: Identifies databases, caches, and file systems
- **Data Flow Detection**: Identifies how data moves between components
- **Outputs in Multiple Formats**: Generates reports in markdown, HTML, CSV, and JSON
- **DFD Generation**: Creates data flow diagrams in DOT (GraphViz) and Mermaid formats
- **Sensitive Data Identification**: Flags potentially sensitive fields based on naming patterns

## Prerequisites

- Linux operating system
- Java 11 or higher
- Maven

## Installation

1. Clone or download this repository to your local machine.
2. Run the setup script to create the project structure:

```bash
chmod +x setup.sh
./setup.sh
```

3. Build the project:

```bash
cd java-dfd-analyzer
mvn clean package
```

## Usage

You can use the provided build-and-run script to simplify execution:

```bash
chmod +x build-and-run.sh
./build-and-run.sh /path/to/your/java/project
```

Or run the application directly:

```bash
java -jar java-dfd-analyzer/target/java-dfd-analyzer-1.0-SNAPSHOT-jar-with-dependencies.jar \
    --path /path/to/your/java/project \
    --output /path/to/output/directory \
    --format markdown \
    --generate-dfd true
```

### Command-Line Options

- `--path` or `-p`: Path to the Java project to analyze (required)
- `--output` or `-o`: Output directory for generated files (required)
- `--format` or `-f`: Output format (markdown, html, csv, json) - default is markdown
- `--generate-dfd`: Whether to generate DFD diagrams (true/false) - default is true

## Output Files

The analyzer generates the following output files:

- `analysis-result.md` or `.html`/`.json`/`.csv`: The main analysis report
- `data-flow-diagram.dot`: A GraphViz DOT file for the data flow diagram
- `data-flow-diagram.mmd`: A Mermaid diagram for the data flow diagram

### Visualizing the DFD

To visualize the DOT file, you can use GraphViz:

```bash
sudo apt-get install graphviz
dot -Tpng -o data-flow-diagram.png /path/to/output/directory/data-flow-diagram.dot
```

To visualize the Mermaid diagram, you can use an online Mermaid editor like [Mermaid Live Editor](https://mermaid.live/) or use a Markdown editor that supports Mermaid diagrams.

## Example Output

### Data Structure Analysis

```markdown
## Data Structures

### UserDTO

- **Type**: DTO
- **Description**: Data Transfer Object for user information
- **Source File**: /path/to/project/src/main/java/com/example/dto/UserDTO.java

#### Fields

| Field | Type | Description |
|-------|------|-------------|
| **password** [SENSITIVE] | String | User's password |
| username | String | User's login name |
| email | String | User's email address |
```

### Data Flow Diagram

```mermaid
flowchart LR
  %% External Entities
  WebClient_UserController["WebClient-UserController"] style fill:#d0e0ff,stroke:#0000ff

  %% Processes
  UserController_getUser((UserController.getUser)) style fill:#d0ffd0,stroke:#00aa00
  UserService_findById((UserService.findById)) style fill:#d0ffd0,stroke:#00aa00

  %% Data Stores
  UserRepository[(UserRepository)] style fill:#ffffd0,stroke:#aaaa00

  %% Data Flows
  WebClient_UserController -->|UserId<br>HTTP| UserController_getUser style color:#0000ff
  UserController_getUser -->|UserId| UserService_findById
  UserService_findById -->|UserId| UserRepository style color:#aa00aa,stroke-dasharray:5 5
  UserRepository -->|UserDTO| UserService_findById style color:#aa00aa,stroke-dasharray:5 5
  UserService_findById -->|UserDTO| UserController_getUser
  UserController_getUser -->|UserDTO<br>HTTP| WebClient_UserController style color:#00aa00
```

## How It Works

1. **Java Project Parsing**: The analyzer uses JavaParser to parse all Java files in the specified project
2. **Code Analysis**: It analyzes the parsed code to identify data structures, external entities, processes, and data stores
3. **Data Flow Detection**: It identifies data flows between components based on method signatures and naming patterns
4. **Report Generation**: It generates a comprehensive report in the specified format
5. **DFD Generation**: It generates data flow diagrams in DOT and Mermaid formats

## Limitations

- The analyzer relies on naming conventions and patterns to identify components, so accuracy depends on code quality
- Complex or non-standard code structures might not be identified correctly
- Dynamic runtime behavior can't be fully captured through static analysis
- The analyzer doesn't currently support multi-module Maven or Gradle projects

## Contributing

Contributions are welcome! Feel free to open issues or pull requests for any improvements or bug fixes.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
