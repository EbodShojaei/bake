import {
  Address,
  Artifact,
  ArtifactLocation,
  Attachment,
  CodeFlow,
  Conversion,
  ExternalProperties,
  ExternalPropertyFileReferences,
  Fix,
  Graph,
  GraphTraversal,
  Invocation,
  Location,
  Log,
  LogicalLocation,
  Message,
  MultiformatMessageString,
  PropertyBag,
  ReportingConfiguration,
  ReportingDescriptorReference,
  ReportingDescriptorRelationship,
  Result,
  ResultProvenance,
  Run,
  RunAutomationDetails,
  SpecialLocations,
  Stack,
  Suppression,
  ThreadFlowLocation,
  Tool,
  ToolComponent,
  VersionControlDetails,
  WebRequest,
  WebResponse
} from 'sarif'

export interface LogOptions {
  /**
   * The URI of the JSON schema corresponding to the version.
   */
  $schema?: string | undefined;

  /**
   * The SARIF format version of this log file.
   */
  version?: Log.version;

  /**
   * The set of runs contained in this log file.
   */
  runs?: Run[];

  /**
   * References to external property files that share data between runs.
   */
  inlineExternalProperties?: ExternalProperties[] | undefined;

  /**
   * Key/value pairs that provide additional information about the log file.
   */
  properties?: PropertyBag | undefined;
}

/**
 * Describes a single run of an analysis tool, and contains the reported output of that run.
 */
export interface SarifRunOptions {
  /**
   * Addresses associated with this run instance, if any.
   */
  addresses?: Address[] | undefined;

  /**
   * An array of artifact objects relevant to the run.
   */
  artifacts?: Artifact[] | undefined;

  /**
   * Automation details that describe this run.
   */
  automationDetails?: RunAutomationDetails | undefined;

  /**
   * The 'guid' property of a previous SARIF 'run' that comprises the baseline that was used to compute result
   * 'baselineState' properties for the run.
   */
  baselineGuid?: string | undefined;

  /**
   * Specifies the unit in which the tool measures columns.
   */
  columnKind?: Run.columnKind | undefined;

  /**
   * A conversion object that describes how a converter transformed an analysis tool's native reporting format into
   * the SARIF format.
   */
  conversion?: Conversion | undefined;

  /**
   * Specifies the default encoding for any artifact object that refers to a text file.
   */
  defaultEncoding?: string | undefined;

  /**
   * Specifies the default source language for any artifact object that refers to a text file that contains source
   * code.
   */
  defaultSourceLanguage?: string | undefined;

  /**
   * References to external property files that should be inlined with the content of a root log file.
   */
  externalPropertyFileReferences?: ExternalPropertyFileReferences | undefined;

  /**
   * An array of zero or more unique graph objects associated with the run.
   */
  graphs?: Graph[] | undefined;

  /**
   * Describes the invocation of the analysis tool.
   */
  invocations?: Invocation[] | undefined;

  /**
   * The language of the messages emitted into the log file during this run (expressed as an ISO 639-1 two-letter
   * lowercase culture code) and an optional region (expressed as an ISO 3166-1 two-letter uppercase subculture code
   * associated with a country or region). The casing is recommended but not required (in order for this data to
   * conform to RFC5646).
   */
  language?: string | undefined;

  /**
   * An array of logical locations such as namespaces, types or functions.
   */
  logicalLocations?: LogicalLocation[] | undefined;

  /**
   * An ordered list of character sequences that were treated as line breaks when computing region information for
   * the run.
   */
  newlineSequences?: string[] | undefined;

  /**
   * The artifact location specified by each uriBaseId symbol on the machine where the tool originally ran.
   */
  originalUriBaseIds?: { [key: string]: ArtifactLocation } | undefined;

  /**
   * Contains configurations that may potentially override both reportingDescriptor.defaultConfiguration (the tool's
   * default severities) and invocation.configurationOverrides (severities established at run-time from the command
   * line).
   */
  policies?: ToolComponent[] | undefined;

  /**
   * An array of strings used to replace sensitive information in a redaction-aware property.
   */
  redactionTokens?: string[] | undefined;

  /**
   * The set of results contained in an SARIF log. The results array can be omitted when a run is solely exporting
   * rules metadata. It must be present (but may be empty) if a log file represents an actual scan.
   */
  results?: Result[] | undefined;

  /**
   * Automation details that describe the aggregate of runs to which this run belongs.
   */
  runAggregates?: RunAutomationDetails[] | undefined;

  /**
   * A specialLocations object that defines locations of special significance to SARIF consumers.
   */
  specialLocations?: SpecialLocations | undefined;

  /**
   * An array of toolComponent objects relevant to a taxonomy in which results are categorized.
   */
  taxonomies?: ToolComponent[] | undefined;

  /**
   * An array of threadFlowLocation objects cached at run level.
   */
  threadFlowLocations?: ThreadFlowLocation[] | undefined;

  /**
   * Information about the tool or tool pipeline that generated the results in this run. A run can only contain
   * results produced by a single tool or tool pipeline. A run can aggregate results from multiple log files, as long
   * as context around the tool run (tool command-line arguments and the like) is identical for all aggregated files.
   */
  tool?: Tool;

  /**
   * The set of available translations of the localized data provided by the tool.
   */
  translations?: ToolComponent[] | undefined;

  /**
   * Specifies the revision in version control of the artifacts that were scanned.
   */
  versionControlProvenance?: VersionControlDetails[] | undefined;

  /**
   * An array of request objects cached at run level.
   */
  webRequests?: WebRequest[] | undefined;

  /**
   * An array of response objects cached at run level.
   */
  webResponses?: WebResponse[] | undefined;

  /**
   * Key/value pairs that provide additional information about the run.
   */
  properties?: PropertyBag | undefined;
}

export interface SarifRuleOptions {
  /**
   * Default reporting configuration information.
   */
  defaultConfiguration?: ReportingConfiguration | undefined;

  /**
   * An array of unique identifies in the form of a GUID by which this report was known in some previous version of
   * the analysis tool.
   */
  deprecatedGuids?: string[] | undefined;

  /**
   * An array of stable, opaque identifiers by which this report was known in some previous version of the analysis
   * tool.
   */
  deprecatedIds?: string[] | undefined;

  /**
   * An array of readable identifiers by which this report was known in some previous version of the analysis tool.
   */
  deprecatedNames?: string[] | undefined;

  /**
   * A description of the report. Should, as far as possible, provide details sufficient to enable resolution of any
   * problem indicated by the result.
   */
  fullDescription?: MultiformatMessageString | undefined;

  /**
   * A unique identifer for the reporting descriptor in the form of a GUID.
   */
  guid?: string | undefined;

  /**
   * Provides the primary documentation for the report, useful when there is no online documentation.
   */
  help?: MultiformatMessageString | undefined;

  /**
   * A URI where the primary documentation for the report can be found.
   */
  helpUri?: string | undefined;

  /**
   * A stable, opaque identifier for the report.
   */
  id?: string;

  /**
   * A set of name/value pairs with arbitrary names. Each value is a multiformatMessageString object, which holds
   * message strings in plain text and (optionally) Markdown format. The strings can include placeholders, which can
   * be used to construct a message in combination with an arbitrary number of additional string arguments.
   */
  messageStrings?: { [key: string]: MultiformatMessageString } | undefined;

  /**
   * A report identifier that is understandable to an end user.
   */
  name?: string | undefined;

  /**
   * An array of objects that describe relationships between this reporting descriptor and others.
   */
  relationships?: ReportingDescriptorRelationship[] | undefined;

  /**
   * A concise description of the report. Should be a single sentence that is understandable when visible space is
   * limited to a single line of text.
   */
  shortDescription?: MultiformatMessageString | undefined;

  /**
   * Key/value pairs that provide additional information about the report.
   */
  properties?: PropertyBag | undefined;
}

export interface SarifResultOptions {
  /**
   * Identifies the artifact that the analysis tool was instructed to scan. This need not be the same as the artifact
   * where the result actually occurred.
   */
  analysisTarget?: ArtifactLocation | undefined;

  /**
   * A set of artifacts relevant to the result.
   */
  attachments?: Attachment[] | undefined;

  /**
   * The state of a result relative to a baseline of a previous run.
   */
  baselineState?: Result.baselineState | undefined;

  /**
   * An array of 'codeFlow' objects relevant to the result.
   */
  codeFlows?: CodeFlow[] | undefined;

  /**
   * A stable, unique identifier for the equivalence class of logically identical results to which this result
   * belongs, in the form of a GUID.
   */
  correlationGuid?: string | undefined;

  /**
   * A set of strings each of which individually defines a stable, unique identity for the result.
   */
  fingerprints?: { [key: string]: string } | undefined;

  /**
   * An array of 'fix' objects, each of which represents a proposed fix to the problem indicated by the result.
   */
  fixes?: Fix[] | undefined;

  /**
   * An array of zero or more unique graph objects associated with the result.
   */
  graphs?: Graph[] | undefined;

  /**
   * An array of one or more unique 'graphTraversal' objects.
   */
  graphTraversals?: GraphTraversal[] | undefined;

  /**
   * A stable, unique identifer for the result in the form of a GUID.
   */
  guid?: string | undefined;

  /**
   * An absolute URI at which the result can be viewed.
   */
  hostedViewerUri?: string | undefined;

  /**
   * A value that categorizes results by evaluation state.
   */
  kind?: Result.kind | undefined;

  /**
   * A value specifying the severity level of the result.
   */
  level?: Result.level | undefined;

  /**
   * The set of locations where the result was detected. Specify only one location unless the problem indicated by
   * the result can only be corrected by making a change at every specified location.
   */
  locations?: Location[] | undefined;

  /**
   * A message that describes the result. The first sentence of the message only will be displayed when visible space
   * is limited.
   */
  message?: Message;

  /**
   * A positive integer specifying the number of times this logically unique result was observed in this run.
   */
  occurrenceCount?: number | undefined;

  /**
   * A set of strings that contribute to the stable, unique identity of the result.
   */
  partialFingerprints?: { [key: string]: string } | undefined;

  /**
   * Information about how and when the result was detected.
   */
  provenance?: ResultProvenance | undefined;

  /**
   * A number representing the priority or importance of the result.
   */
  rank?: number | undefined;

  /**
   * A set of locations relevant to this result.
   */
  relatedLocations?: Location[] | undefined;

  /**
   * A reference used to locate the rule descriptor relevant to this result.
   */
  rule?: ReportingDescriptorReference | undefined;

  /**
   * The stable, unique identifier of the rule, if any, to which this notification is relevant. This member can be
   * used to retrieve rule metadata from the rules dictionary, if it exists.
   */
  ruleId?: string | undefined;

  /**
   * The index within the tool component rules array of the rule object associated with this result.
   */
  ruleIndex?: number | undefined;

  /**
   * An array of 'stack' objects relevant to the result.
   */
  stacks?: Stack[] | undefined;

  /**
   * A set of suppressions relevant to this result.
   */
  suppressions?: Suppression[] | undefined;

  /**
   * An array of references to taxonomy reporting descriptors that are applicable to the result.
   */
  taxa?: ReportingDescriptorReference[] | undefined;

  /**
   * A web request associated with this result.
   */
  webRequest?: WebRequest | undefined;

  /**
   * A web response associated with this result.
   */
  webResponse?: WebResponse | undefined;

  /**
   * The URIs of the work items associated with this result.
   */
  workItemUris?: string[] | undefined;

  /**
   * Key/value pairs that provide additional information about the result.
   */
  properties?: PropertyBag | undefined;
}
