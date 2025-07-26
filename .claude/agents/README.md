# Solidity Multi-Agent Development System

This folder contains 8 specialized agents for comprehensive Solidity smart contract development using 2025 best practices. Each agent has distinct responsibilities and coordinates with others for seamless development workflow.

## Agent Overview

### 🏗️ **Core Development Agents** (High Priority)

#### 1. **Architect Agent** (`architect.md`)
- **Primary Role**: System design, architecture planning, and requirements analysis
- **Key Functions**: Creates implementation roadmaps, defines system boundaries, coordinates all agents
- **When to Use**: Start here for any new project or major architectural decisions

#### 2. **Developer Agent** (`developer.md`) 
- **Primary Role**: Smart contract implementation using Foundry/Forge
- **Key Functions**: Phase-based development, code implementation, dependency management
- **When to Use**: After architecture is defined, for actual contract coding

#### 3. **Tester Agent** (`tester.md`)
- **Primary Role**: Comprehensive testing and quality assurance
- **Key Functions**: Unit/fuzz/invariant testing, >95% coverage, bug reporting
- **When to Use**: After implementation, for thorough testing and validation
- **Critical Rule**: NEVER modifies tests to pass - always reports bugs

#### 4. **Security Auditor Agent** (`security-auditor.md`)
- **Primary Role**: Security analysis and vulnerability assessment
- **Key Functions**: OWASP-based audits, threat modeling, attack simulation
- **When to Use**: After development phases, for security validation

### 🔧 **Specialized Support Agents** (Medium Priority)

#### 5. **Gas Optimizer Agent** (`gas-optimizer.md`)
- **Primary Role**: Gas consumption optimization and performance tuning
- **Key Functions**: Assembly optimizations, storage patterns, gas analysis
- **When to Use**: After core functionality is working, for efficiency improvements

#### 6. **Deployer Agent** (`deployer.md`)
- **Primary Role**: Deployment, verification, and post-deployment management
- **Key Functions**: Multi-network deployment, monitoring, emergency procedures
- **When to Use**: Final phase for production deployment and maintenance

#### 7. **Documentation Agent** (`documentation.md`)
- **Primary Role**: Comprehensive documentation and knowledge management
- **Key Functions**: NatSpec documentation, user guides, API docs
- **When to Use**: Throughout development for maintaining documentation

#### 8. **Integration Agent** (`integration.md`)
- **Primary Role**: External API and cross-chain integration
- **Key Functions**: Oracle integration, cross-chain bridges, external APIs
- **When to Use**: When connecting contracts to external systems

## Workflow Coordination

### **Phase 1: Planning & Architecture**
1. **Architect Agent** analyzes requirements and designs system
2. Hands off specifications to other agents

### **Phase 2: Core Development**
1. **Developer Agent** implements contracts following architecture
2. **Tester Agent** creates comprehensive test suites
3. **Security Auditor Agent** performs initial security review

### **Phase 3: Optimization & Security**
1. **Gas Optimizer Agent** optimizes performance
2. **Security Auditor Agent** performs final security audit
3. **Tester Agent** validates all optimizations

### **Phase 4: Integration & Deployment**
1. **Integration Agent** connects external systems
2. **Deployer Agent** handles production deployment
3. **Documentation Agent** finalizes all documentation

## Key Principles

### **Security First**
- All agents prioritize security over convenience
- Security Auditor Agent has veto power over implementations
- Never compromise security for gas optimization

### **Testing Integrity** 
- Tester Agent NEVER modifies tests to make them pass
- All bugs are reported to Developer Agent for proper fixes
- >95% test coverage required before deployment

### **Collaborative Development**
- Clear handoff procedures between agents
- Each agent knows others' roles and responsibilities
- Systematic workflow prevents missed requirements

### **2025 Standards**
- Latest Solidity 0.8.30+ features
- Foundry v1.0 optimization and testing
- OWASP Smart Contract Top 10 compliance
- Gas optimization with assembly where appropriate

## Usage Instructions

### **For New Projects:**
1. Start with `architect.md` for system design
2. Use `developer.md` for implementation
3. Apply `tester.md` for comprehensive testing
4. Engage `security-auditor.md` for security validation
5. Use specialized agents as needed

### **For Existing Projects:**
- Use specific agents based on current needs
- Follow established handoff procedures
- Maintain documentation throughout

### **Emergency Procedures:**
- `security-auditor.md` for security incidents
- `deployer.md` for deployment issues
- All agents coordinate for emergency response

## File Structure

```
agents/
├── README.md                 # This overview file
├── architect.md             # solidity-architect: System design and planning
├── developer.md             # solidity-developer: Contract implementation  
├── tester.md                # solidity-tester: Testing and QA
├── security-auditor.md      # solidity-security-auditor: Security analysis
├── gas-optimizer.md         # solidity-gas-optimizer: Performance optimization
├── deployer.md              # solidity-deployer: Deployment management
├── documentation.md         # solidity-documentation: Documentation creation
└── integration.md           # solidity-integration: External integrations
```

### **Agent Names and Descriptions**

Each agent includes proper Claude agent frontmatter:

```yaml
---
name: solidity-[role]
description: [Detailed description of agent capabilities and responsibilities]
---
```

**Available Agents:**
- `solidity-architect` - System architecture and planning specialist
- `solidity-developer` - Smart contract implementation specialist  
- `solidity-tester` - Comprehensive testing and QA specialist
- `solidity-security-auditor` - Security analysis and vulnerability assessment specialist
- `solidity-gas-optimizer` - Gas optimization and performance specialist
- `solidity-deployer` - Deployment and post-deployment management specialist
- `solidity-documentation` - Documentation and knowledge management specialist
- `solidity-integration` - External integration and connectivity specialist

## Integration with Claude Code

These agents are designed to work with Claude Code's sub-agent functionality. Each agent:

- Has specialized knowledge for its domain
- Coordinates with other agents through clear protocols
- Maintains context and state throughout development
- Provides detailed technical guidance and implementation

## Getting Started

1. **Choose Your Starting Point**: For new projects, begin with `architect.md`
2. **Follow the Workflow**: Each agent specifies handoff procedures to others
3. **Maintain Quality**: Use testing and security agents throughout development
4. **Document Everything**: Documentation agent ensures knowledge preservation

Remember: This is a comprehensive system where each agent specializes in their domain while maintaining awareness of the entire development ecosystem. The result is professional-grade Solidity development that meets 2025 industry standards.