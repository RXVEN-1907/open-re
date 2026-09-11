//! Core types, errors, and traits for open-re

pub mod app_map;
pub mod attack_path;
pub mod deduplication;
pub mod error;
pub mod evidence;
pub mod history;
pub mod ids;
pub mod plugin;
pub mod relationships;
pub mod remediation;
pub mod reporting;
pub mod result;
pub mod risk_knowledge;
pub mod traits;

// Re-export all modules with explicit exports to avoid ambiguous glob re-exports
pub use app_map::TargetInfo;
pub use app_map::{
    ApplicationMap, AuthEndpoint, AuthRequirement, AuthType, CorsInfo, DiscoverySource, Endpoint,
    HttpMethod, Parameter, ParameterLocation, ParameterValidation, RateLimitInfo, Resource,
    SensitivityLevel, Technology, UrlNode,
};
pub use attack_path::{
    AttackComplexity, AttackNodeType, AttackPath, AttackPathCollection, AttackPathEdge,
    AttackPathNode, AttackStage, AttackTechnique, AttackVector, BusinessImpact, DetectionMethod,
    DetectionOpportunity, EntryPoint, EvidenceRef, ExploitabilityInfo, FalsePositiveLikelihood,
    ImpactAssessment, ImpactDetail, ImpactLevel, MitigationEffectiveness, MitigationPriority,
    MitigationRecommendation, NodeId, Prerequisite, PrerequisiteType, PrivilegeLevel,
    PrivilegesRequired, RemediationEffort, RiskLevel, RiskScore, RiskScoreBreakdown, Scope,
    UserInteraction,
};
pub use deduplication::{
    CorrelationAttackPath, CorrelationAttackStep, CorrelationChain, CorrelationConfig,
    CorrelationEngine, CorrelationResult, CorrelationType, DeduplicationConfig,
    DeduplicationEngine, DeduplicationReason, DeduplicationResult, DuplicateGroup,
    FindingCorrelation,
};
pub use error::*;
pub use evidence::{
    ExtractedData, ExtractedDataType, FindingEvidence, FindingVerifier, HttpInteraction,
    ResponseAnalysis, ResponseDiff, SignificantChange, TriggerCondition, VerificationEvidence,
    VerificationMethod, VerificationResult, VerificationStatus,
};
pub use history::*;
pub use ids::*;
pub use plugin::*;
pub use relationships::{
    EvidenceSource, EvidenceType, FindingRelationship, FindingRelationshipGraph,
    FindingRelationshipType, RelationshipEvidence, RelationshipFilter, RelationshipGraphMetadata,
    RelationshipStats, RiskFactor, RiskImpact, RiskLevelChange,
};
pub use remediation::{
    AuthChanges, AuthMethodChange, EnhancedScanDiff, EvidenceChange, FindingChanges,
    PersistentFinding, RemediationId, SessionChangeType, SessionManagementChange, SeverityChange,
    SeverityChangeType, TechnologyChangeInfo, TechnologyChanges, TechnologyConfigChange,
    TechnologyVersionChange, VerificationChange,
};
pub use reporting::{
    DateRange, ExecutiveSummary, ReportConfig, ReportFormat, ReportGenerator, ReportMetadata,
};
pub use result::*;
pub use risk_knowledge::{
    AttackLikelihood, AuthContext, AuthStrength, BusinessContext, BusinessCriticality,
    CompensatingControl, ControlCoverage, ControlEffectiveness, ControlType, EndpointContext,
    EnvironmentalFactors, ExploitAvailability, ExploitMaturity, ExploitSource, FindingDependency,
    IncidentResponseReadiness, NetworkSegmentation, Reachability, RiskFactors,
    ThreatIntelRelevance, VersionRange,
};
pub use traits::*;

pub use plugin::{
    CapabilityRequest, CapabilityResponse, CapabilitySet, CommandContext, CommandRegistration,
    CommandResult, Plugin, PluginInitInfo, PluginManifest, PluginMetadata, PluginRegistry,
    PluginSdkMetadata, PluginSource, PluginStatus, RegistryConfig, RegistryEntry,
};
