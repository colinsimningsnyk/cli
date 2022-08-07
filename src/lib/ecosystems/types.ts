import { DepGraphData } from '@snyk/dep-graph';
import { PkgInfo } from '@snyk/dep-graph';
import { SEVERITY } from '../snyk-test/common';
import { REACHABILITY, RemediationChanges } from '../snyk-test/legacy';
import {
  Options,
  ProjectAttributes,
  SupportedProjectTypes,
  Tag,
} from '../types';

export type Ecosystem = 'cpp' | 'docker' | 'code';

export type FindingType = 'iacIssue';

export interface PluginResponse {
  scanResults: ScanResult[];
}

export interface GitTarget {
  remoteUrl?: string;
  branch?: string;
}

export interface ContainerTarget {
  image: string;
}

export interface UnknownTarget {
  name: string; // Should be equal to the project name
}

export interface HashFormat {
  format: number;
  data: string;
}

export interface FileHash {
  size: number;
  path: string;
  hashes_ffm: HashFormat[];
}

export interface FileHashes {
  hashes: FileHash[];
}

export interface Dep {
  nodeId: string;
}

export interface Node {
  nodeId: string;
  pkgId: string;
  deps: Dep[];
}

// interface Graph {
//   rootNodeId: string;
//   nodes: Node[];
//   componentDetails: ComponentDetails;
// }

// export interface DepGraphData {
//   schemaVersion: string;
//   pkgManager: PkgManager;
//   pkgs: Pkg[];
//   graph: Graph;
// }

export interface LocationResponse {
  id: string;
  location: string;
  type: string;
}

export interface JsonApi {
  version: string;
}

export interface Links {
  self: string;
}

export interface CreateDepGraphResponse {
  data: LocationResponse;
  jsonapi: JsonApi;
  links: Links;
}

export interface DepOpenApi {
  node_id: string;
}

interface NodeOpenApi {
  node_id: string;
  pkg_id: string;
  deps: DepOpenApi[];
}

export interface Details {
  artifact: string;
  version: string;
  author: string;
  path: string;
  id: string;
  url: string;
  score: string;
  filePaths: string[];
}

export interface ComponentDetails {
  [key: string]: Details;
}

interface GraphOpenApi {
  root_node_id: string;
  nodes: NodeOpenApi[];
  component_details: ComponentDetails;
}

export interface Pkg {
  id: string;
  info: PkgInfo;
}

export interface PkgManager {
  name: string;
}

export interface DepGraphDataOpenAPI {
  schema_version: string;
  pkg_manager: PkgManager;
  pkgs: Pkg[];
  graph: GraphOpenApi;
}

export interface Attributes {
  start_time: number;
  dep_graph_data: DepGraphDataOpenAPI;
  component_details: ComponentDetails;
}

export interface IssuesRequestDetails {
  artifact: string;
  version: string;
  author: string;
  path: string;
  id: string;
  url: string;
  score: string;
  filePaths: string[];
}

export interface IssuesRequestComponentDetails {
  [key: string]: IssuesRequestDetails;
}

export interface IssuesRequestDep {
  nodeId: string;
}

export interface IssuesRequestNode {
  nodeId: string;
  pkgId: string;
  deps: IssuesRequestDep[];
}

export interface IssuesRequestGraph {
  rootNodeId: string;
  nodes: IssuesRequestNode[];
  component_details: ComponentDetails;
}

export interface IssuesRequestDepGraphDataOpenAPI {
  schemaVersion: string;
  pkgManager: PkgManager;
  pkgs: Pkg[];
  graph: IssuesRequestGraph;
}

export interface IssuesRequestAttributes {
  start_time: number;
  dep_graph: IssuesRequestDepGraphDataOpenAPI;
  component_details: IssuesRequestComponentDetails;
}

interface Data {
  id: string;
  type: string;
  attributes: Attributes;
}

export interface FileSignaturesDetailsOpenApi {
  [pkgKey: string]: {
    confidence: number;
    artifact: string;
    varsion: string;
    author: string;
    path: string;
    id: string;
    url: string;
    file_paths: string[];
  };
}

export interface FixInfoOpenApi {
  upgrade_paths: UpgradePath[];
  is_patchable: boolean;
  nearest_fixed_in_version?: string;
}

export interface IssueOpenApi {
  pkg_name: string;
  pkg_version?: string;
  issue_id: string;
  fix_info: FixInfoOpenApi;
}

export interface IssuesDataOpenApi {
  [issueId: string]: IssueDataOpenApi;
}

interface IssuesResponseDataReslut {
  start_time: string;
  issues: IssueOpenApi[];
  issues_data: IssuesDataOpenApi;
  dep_graph: DepGraphDataOpenAPI;
  deps_file_paths: DepsFilePaths;
  file_signatures_details: FileSignaturesDetailsOpenApi;
  type: string;
}

export interface IssuesResponseData {
  id: string;
  result: IssuesResponseDataReslut;
}

export interface GetIssuesResponse {
  jsonapi: JsonApi;
  links: Links;
  data: IssuesResponseData;
}

export interface GetDepGraphResponse {
  data: Data;
  jsonapi: JsonApi;
  links: Links;
}

interface PatchOpenApi {
  version: string;
  id: string;
  urls: string[];
  modification_time: string;
}

export interface IssueDataOpenApi {
  id: string;
  package_name: string;
  version: string;
  module_name?: string;
  below: string; // Vulnerable below version
  semver: {
    vulnerable: string | string[];
    vulnerable_hashes?: string[];
    vulnerable_by_distro?: {
      [distro_name_and_version: string]: string[];
    };
  };
  patches: PatchOpenApi[];
  is_new: boolean;
  description: string;
  title: string;
  severity: SEVERITY;
  fixed_in: string[];
  legal_instructions?: string;
  reachability?: REACHABILITY;
  package_manager?: SupportedProjectTypes;
  from?: string[];
  name?: string;
}

export interface ScanResult {
  identity: Identity;
  facts: Facts[];
  findings?: Finding[];
  name?: string;
  policy?: string;
  target?: GitTarget | ContainerTarget | UnknownTarget;
  analytics?: Analytics[];
  targetReference?: string;
}

export interface Analytics {
  name: string;
  data: unknown;
}

export interface Identity {
  type: string;
  targetFile?: string;
  args?: { [key: string]: string };
}

export interface Facts {
  type: string;
  data: any;
}

export interface Finding {
  type: FindingType;
  data: any;
}

interface UpgradePathItem {
  name: string;
  version: string;
  newVersion?: string;
  isDropped?: boolean;
}

interface UpgradePath {
  path: UpgradePathItem[];
}

export interface FixInfo {
  upgradePaths: UpgradePath[];
  isPatchable: boolean;
  nearestFixedInVersion?: string;
}

export interface Issue {
  pkgName: string;
  pkgVersion?: string;
  issueId: string;
  fixInfo: FixInfo;
}

export interface IssuesData {
  [issueId: string]: {
    id: string;
    severity: SEVERITY;
    title: string;
  };
}

export interface DepsFilePaths {
  [pkgKey: string]: string[];
}

export interface FileSignaturesDetails {
  [pkgKey: string]: {
    confidence: number;
    filePaths: string[];
  };
}

export interface TestResult {
  issues: Issue[];
  issuesData: IssuesData;
  depGraphData: DepGraphData;
  depsFilePaths?: DepsFilePaths;
  fileSignaturesDetails?: FileSignaturesDetails;
  remediation?: RemediationChanges;
}

export interface EcosystemPlugin {
  scan: (options: Options) => Promise<PluginResponse>;
  display: (
    scanResults: ScanResult[],
    testResults: TestResult[],
    errors: string[],
    options: Options,
  ) => Promise<string>;
  test?: (
    paths: string[],
    options: Options,
  ) => Promise<{ readableResult: string; sarifResult?: string }>;
}

export interface EcosystemMonitorError {
  error: string;
  path: string;
  scanResult: ScanResult;
}

export interface MonitorDependenciesResponse {
  ok: boolean;
  org: string;
  id: string;
  isMonitored: boolean;
  licensesPolicy: any;
  uri: string;
  trialStarted: boolean;
  path: string;
  projectName: string;
}

export interface EcosystemMonitorResult extends MonitorDependenciesResponse {
  scanResult: ScanResult;
}

export interface MonitorDependenciesRequest {
  scanResult: ScanResult;

  /**
   * If provided, overrides the default project name (usually equivalent to the root package).
   * @deprecated Must not be set by new code! Prefer to set the "scanResult.name" within your plugin!
   */
  projectName?: string;
  policy?: string;
  method?: 'cli';
  tags?: Tag[];
  attributes?: ProjectAttributes;
}
