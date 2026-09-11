//! Control Flow Graph construction and analysis

use crate::disassembler::Instruction;
use crate::error::{DisasmError, Result};
use petgraph::algo::kosaraju_scc;
use petgraph::graph::{DiGraph, NodeIndex};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Basic block in a control flow graph
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BasicBlock {
    pub id: usize,
    pub start_address: u64,
    pub end_address: u64,
    pub instructions: Vec<u64>,
    pub predecessors: Vec<usize>,
    pub successors: Vec<usize>,
    pub is_entry: bool,
    pub is_exit: bool,
}

/// Edge in a control flow graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CfgEdge {
    pub from: usize,
    pub to: usize,
    pub edge_type: CfgEdgeType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CfgEdgeType {
    Unconditional,
    ConditionalTrue,
    ConditionalFalse,
    Call,
    Return,
    Indirect,
    Exception,
    Fallthrough,
}

/// Control flow graph
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ControlFlowGraph {
    #[serde(skip)]
    pub graph: DiGraph<BasicBlock, CfgEdge>,
    pub entry: Option<usize>,
    pub exits: Vec<usize>,
}

/// Dominator tree for a control flow graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DominatorTree {
    pub idoms: HashMap<usize, usize>,
    pub dominance_frontier: HashMap<usize, Vec<usize>>,
}

/// Loop information for a control flow graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoopInfo {
    pub headers: Vec<usize>,
    pub bodies: Vec<Vec<usize>>,
    pub depth: HashMap<usize, usize>,
}

/// CFG builder for constructing control flow graphs from disassembly
pub struct CfgBuilder {
    instructions: Vec<Instruction>,
    entry_address: u64,
    end_address: Option<u64>,
}

impl CfgBuilder {
    pub fn new(entry_address: u64) -> Self {
        Self { instructions: Vec::new(), entry_address, end_address: None }
    }

    pub fn with_end_address(mut self, end_address: u64) -> Self {
        self.end_address = Some(end_address);
        self
    }

    pub fn add_instruction(mut self, insn: Instruction) -> Self {
        self.instructions.push(insn);
        self
    }

    pub fn add_instructions(mut self, insns: Vec<Instruction>) -> Self {
        self.instructions.extend(insns);
        self
    }

    pub fn build(self) -> Result<ControlFlowGraph> {
        if self.instructions.is_empty() {
            return Err(DisasmError::CfgConstruction("No instructions provided".to_string()));
        }

        // Sort instructions by address
        let mut sorted_insns = self.instructions;
        sorted_insns.sort_by_key(|i| i.address);

        // Simple block boundaries - every instruction is its own block for now
        let mut blocks = Vec::new();
        for (i, insn) in sorted_insns.iter().enumerate() {
            let block = BasicBlock {
                id: i,
                start_address: insn.address,
                end_address: insn.address + insn.size as u64,
                instructions: vec![insn.address],
                predecessors: Vec::new(),
                successors: Vec::new(),
                is_entry: insn.address == self.entry_address,
                is_exit: false,
            };
            blocks.push(block);
        }

        // Build graph
        let mut graph = DiGraph::new();
        let mut node_indices = Vec::new();

        for _ in blocks.iter() {
            node_indices.push(graph.add_node(BasicBlock::default()));
        }

        // Add nodes to graph
        for (i, block) in blocks.into_iter().enumerate() {
            graph[node_indices[i]] = block;
        }

        // Add edges
        for i in 0..node_indices.len() - 1 {
            graph.add_edge(
                node_indices[i],
                node_indices[i + 1],
                CfgEdge { from: i, to: i + 1, edge_type: CfgEdgeType::Fallthrough },
            );
        }

        let entry = Some(0);
        let exits = if node_indices.is_empty() { vec![] } else { vec![node_indices.len() - 1] };

        Ok(ControlFlowGraph { graph, entry, exits })
    }
}

/// Compute dominator tree for a CFG
pub fn compute_dominators(cfg: &ControlFlowGraph) -> Result<DominatorTree> {
    let graph = &cfg.graph;
    let entry =
        cfg.entry.ok_or_else(|| DisasmError::CfgConstruction("No entry node".to_string()))?;
    let entry_idx = NodeIndex::new(entry);

    let doms = petgraph::algo::dominators::simple_fast(graph, entry_idx);

    let mut idoms = HashMap::new();
    let mut dominance_frontier = HashMap::new();

    // Compute immediate dominators
    for node in graph.node_indices() {
        if node == entry_idx {
            continue;
        }
        if let Some(idom) = doms.immediate_dominator(node) {
            idoms.insert(node.index(), idom.index());
        }
    }

    // Compute dominance frontiers
    for node in graph.node_indices() {
        let mut frontier = Vec::new();

        // Get all dominators of this node (including itself)
        let node_doms: std::collections::HashSet<NodeIndex> =
            if let Some(iter) = doms.dominators(node) {
                iter.collect()
            } else {
                std::collections::HashSet::new()
            };

        for succ in graph.neighbors(node) {
            let succ_doms: std::collections::HashSet<NodeIndex> =
                if let Some(iter) = doms.dominators(succ) {
                    iter.collect()
                } else {
                    std::collections::HashSet::new()
                };

            if !node_doms.contains(&succ) || !succ_doms.iter().all(|d| node_doms.contains(d)) {
                frontier.push(succ.index());
            }
        }
        if !frontier.is_empty() {
            dominance_frontier.insert(node.index(), frontier);
        }
    }

    Ok(DominatorTree { idoms, dominance_frontier })
}

/// Find loops in a CFG
pub fn find_loops(cfg: &ControlFlowGraph) -> Result<LoopInfo> {
    let graph = &cfg.graph;
    let sccs = kosaraju_scc(graph);

    let mut headers = Vec::new();
    let mut bodies = Vec::new();
    let mut depth = HashMap::new();

    for scc in sccs {
        if scc.len() > 1 || (scc.len() == 1 && graph.neighbors(scc[0]).any(|n| n == scc[0])) {
            let header = scc[0];
            headers.push(header.index());
            bodies.push(scc.iter().map(|n| n.index()).collect());
            for &node in &scc {
                depth.insert(node.index(), depth.get(&node.index()).copied().unwrap_or(0) + 1);
            }
        }
    }

    Ok(LoopInfo { headers, bodies, depth })
}
