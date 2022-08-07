import { Options, PolicyOptions } from '../types';
import { spinner } from '../../lib/spinner';
import {
  Attributes,
  CreateDepGraphResponse,
  Ecosystem,
  FileHash,
  GetIssuesResponse,
  HashFormat,
  IssuesRequestAttributes,
  IssuesRequestDepGraphDataOpenAPI,
  ScanResult,
  TestResult,
  Pkg,
  PkgManager,
  IssuesRequestGraph,
  IssuesRequestNode,
  IssuesRequestDep,
  IssuesRequestComponentDetails,
  IssuesRequestDetails,
  GetDepGraphResponse,
  IssueOpenApi,
  FixInfo,
  IssuesDataOpenApi,
  FileSignaturesDetails,
  FileSignaturesDetailsOpenApi,
  DepGraphDataOpenAPI,
  Node,
  Dep,
  ComponentDetails,
} from './types';
import {
  requestTestPollingToken,
  pollingTestWithTokenUntilDone,
  createDepGraph,
  getDepGraph,
  getIssues,
} from '../polling/polling-test';
import { extractAndApplyPluginAnalytics } from './plugin-analytics';
import { findAndLoadPolicy } from '../policy';
import { filterIgnoredIssues } from './policy';
import { IssueData, Issue, Patch } from '../snyk-test/legacy';
import { isUnmanagedEcosystem } from './common';
import { hasFeatureFlag } from '../feature-flags';
import { delayNextStep } from '../polling/common';

interface Graph {
  rootNodeId: string;
  nodes: Node[];
  componentDetails: ComponentDetails;
}

export interface DepGraphData {
  schemaVersion: string;
  pkgManager: PkgManager;
  pkgs: Pkg[];
  graph: Graph;
}

export async function resolveAndTestFacts(
  ecosystem: Ecosystem,
  scans: {
    [dir: string]: ScanResult[];
  },
  options: Options & PolicyOptions,
): Promise<[TestResult[], string[]]> {
  const enhancedOptions = { ...options };

  if (isUnmanagedEcosystem(ecosystem)) {
    enhancedOptions.supportSnykNewUnmanagedTest = await hasFeatureFlag(
      'snykNewUnmanagedTest',
      options,
    );
  }

  return enhancedOptions.supportSnykNewUnmanagedTest
    ? resolveAndTestFactsNew(ecosystem, scans, options)
    : resolveAndTestFactsLegacy(ecosystem, scans, options);
}

function convertDepGraphAttributes(attributes: Attributes) {
  const pkgManager: PkgManager = {
    name: attributes?.dep_graph_data?.pkg_manager?.name,
  };

  const pkgs = [] as Pkg[];
  for (let i = 0; i < attributes?.dep_graph_data?.pkgs.length; i++) {
    pkgs.push(attributes?.dep_graph_data?.pkgs[i]);
  }

  const graph = {} as IssuesRequestGraph;
  const nodes = [] as IssuesRequestNode[];
  graph.rootNodeId = attributes?.dep_graph_data?.graph?.root_node_id;
  for (let i = 0; i < attributes?.dep_graph_data?.graph?.nodes?.length; i++) {
    const node = {} as IssuesRequestNode;
    node.nodeId = attributes?.dep_graph_data?.graph?.nodes[i]?.node_id;
    node.pkgId = attributes?.dep_graph_data?.graph?.nodes[i]?.pkg_id;
    const deps = [] as IssuesRequestDep[];
    for (
      let j = 0;
      j < attributes?.dep_graph_data?.graph?.nodes[i].deps?.length;
      j++
    ) {
      deps.push({
        nodeId: attributes?.dep_graph_data?.graph?.nodes[i].deps[j]?.node_id,
      });
    }
    node.deps = deps;
    nodes.push(node);
  }
  graph.nodes = nodes;

  const depGraph: IssuesRequestDepGraphDataOpenAPI = {
    schemaVersion: attributes?.dep_graph_data?.schema_version,
    pkgManager: pkgManager,
    pkgs,
    graph,
  };

  const componentDetails = {} as IssuesRequestComponentDetails;
  for (const key in attributes?.component_details) {
    const details = attributes?.component_details[key];
    const filePaths: string[] = [];
    for (const fileIndex in details?.filePaths) {
      filePaths.push(details?.filePaths[fileIndex]);
    }
    const isuueDetails: IssuesRequestDetails = {
      artifact: details?.artifact,
      version: details?.version,
      author: details?.author,
      path: details?.path,
      id: details?.id,
      url: details?.url,
      score: details?.score,
      filePaths: filePaths,
    };
    componentDetails[key] = isuueDetails;
  }

  const issuesRequestAttributes: IssuesRequestAttributes = {
    start_time: attributes?.start_time,
    dep_graph: depGraph,
    component_details: componentDetails,
  };

  return issuesRequestAttributes;
}

function convertScanResultsToHashes(scanResult: ScanResult) {
  const hashesArray: FileHash[] = [];
  for (const data of scanResult.facts[0].data) {
    const path = data.path;
    const size = data.size;
    const hashesFfm: HashFormat[] = [];
    for (const h of data.hashes_ffm) {
      h.data;
      const format = h.format;
      const data = h.data;
      const hashFormat: HashFormat = { data, format };
      hashesFfm.push(hashFormat);
    }
    const hash: FileHash = { size: size, path: path, hashes_ffm: hashesFfm };
    hashesArray.push(hash);
  }
  return hashesArray;
}

function convertIssues(issuesOpenApi: IssueOpenApi[]) {
  const issues: Issue[] = [];

  for (let i = 0; i < issuesOpenApi.length; i++) {
    const fInfo: FixInfo = {
      upgradePaths: issuesOpenApi[i].fix_info.upgrade_paths,
      isPatchable: issuesOpenApi[i].fix_info.is_patchable,
      nearestFixedInVersion: issuesOpenApi[i].fix_info.nearest_fixed_in_version,
    };
    const issue: Issue = {
      pkgName: issuesOpenApi[i].pkg_name,
      pkgVersion: issuesOpenApi[i].pkg_version,
      issueId: issuesOpenApi[i].issue_id,
      fixInfo: fInfo,
    };

    issue.issueId = issuesOpenApi[i].issue_id;
    issues.push(issue);
  }

  return issues;
}

function convertIssuesData(issuesDataOpenApi: IssuesDataOpenApi) {
  const issuesData: { [issueId: string]: IssueData } = {};

  for (const key in issuesDataOpenApi) {
    const issueData: IssueData = {} as IssueData;
    issueData.name = issuesDataOpenApi[key].name;
    issueData.id = issuesDataOpenApi[key].id;
    issueData.packageName = issuesDataOpenApi[key].package_name;
    issueData.version = issuesDataOpenApi[key].version;
    issueData.moduleName = issuesDataOpenApi[key].module_name;
    issueData.below = issuesDataOpenApi[key].below;
    //TODO: do we need this for C/C++?
    // issueData.semver = issuesDataOpenApi[key].semver;
    // issueData.semver.vulnerableHashes = issuesDataOpenApi[key].semver.vulnerable_hashes;
    // issuesDataOpenApi[key].semver.vulnerable_by_distro;
    issueData.patches = [] as Patch[];
    issuesDataOpenApi[key].patches.forEach((x) => {
      issueData.patches.push({
        version: x.version,
        id: x.id,
        urls: x.urls,
        modificationTime: x.modification_time,
      } as Patch);
    });
    issueData.isNew = issuesDataOpenApi[key].is_new;
    issueData.description = issuesDataOpenApi[key].description;
    issueData.title = issuesDataOpenApi[key].title;
    issueData.severity = issuesDataOpenApi[key].severity;
    issueData.fixedIn = issuesDataOpenApi[key].fixed_in;
    issueData.legalInstructions = issuesDataOpenApi[key].legal_instructions;
    issueData.reachability = issuesDataOpenApi[key].reachability;
    issueData.packageManager = issuesDataOpenApi[key].package_manager;
    issueData.from = issuesDataOpenApi[key].from;
    issueData.name = issuesDataOpenApi[key].name;
    //issuesData.push(issueData);
    issuesData[key] = issueData;
  }
  return issuesData;
}

function convertFileSignatures(
  fileSignatureDetailsOpenApi: FileSignaturesDetailsOpenApi,
) {
  const fileSignaturesDetails = {} as FileSignaturesDetails;

  for (const fileSignatureDetailOpenApiKey in fileSignatureDetailsOpenApi) {
    const filePath: string[] = [];
    fileSignatureDetailsOpenApi[
      fileSignatureDetailOpenApiKey
    ].file_paths.forEach((f) => {
      filePath.push(f);
    });
    const fileSignaturesDetail = {
      confidence:
        fileSignatureDetailsOpenApi[fileSignatureDetailOpenApiKey].confidence,
      filePaths: filePath,
    };
    fileSignaturesDetails[fileSignatureDetailOpenApiKey] = fileSignaturesDetail;
  }

  return fileSignaturesDetails;
}

function convertDepGraph(depGraphOpenApi: DepGraphDataOpenAPI) {
  const depGraph = {} as DepGraphData;

  depGraph.pkgManager = depGraphOpenApi.pkg_manager;
  depGraph.schemaVersion = depGraphOpenApi.schema_version;
  depGraph.pkgs = depGraphOpenApi.pkgs;

  depGraph.graph = {} as Graph;
  depGraph.graph.rootNodeId = depGraphOpenApi.graph.root_node_id;

  depGraph.graph.nodes = [] as Node[];
  depGraphOpenApi.graph.nodes.forEach((n) => {
    const deps: Dep[] = [];
    for (let i = 0; i < n.deps.length; i++) {
      deps.push({ nodeId: n.deps[i].node_id });
    }
    depGraph.graph.nodes.push({
      nodeId: n.node_id,
      pkgId: n.pkg_id,
      deps: deps,
    } as Node);
  });
  return depGraph;
}

export async function resolveAndTestFactsNew(
  ecosystem: Ecosystem,
  scans: {
    [dir: string]: ScanResult[];
  },
  options: Options & PolicyOptions,
): Promise<[TestResult[], string[]]> {
  const results: any[] = [];
  const errors: string[] = [];
  const packageManager = 'Unmanaged (C/C++)';

  for (const [path, scanResults] of Object.entries(scans)) {
    await spinner(`Resolving and Testing fileSignatures in ${path}`);
    for (const scanResult of scanResults) {
      try {
        const hashesArray = convertScanResultsToHashes(scanResult);

        const createDepGraphResponse: CreateDepGraphResponse = await createDepGraph(
          { hashes: hashesArray },
        );
        const id = createDepGraphResponse.data?.id;

        let attempts = 0;
        const maxAttempts = 50;
        let getDepGraphResponse = {} as GetDepGraphResponse;
        while (attempts < maxAttempts) {
          await delayNextStep(attempts, maxAttempts, 1000);
          try {
            getDepGraphResponse = await getDepGraph(
              { hashes: hashesArray },
              id,
            );
            break;
          } catch (e) {
            attempts--;
          }
        }
        if (attempts >= maxAttempts) {
          throw new Error('Failed to get DepGraph');
        }

        const depGrapAttributes = convertDepGraphAttributes(
          getDepGraphResponse?.data?.attributes,
        );

        const getIssuesResponse: GetIssuesResponse = await getIssues(
          depGrapAttributes,
        );

        const resIssues = convertIssues(getIssuesResponse.data.result.issues);
        const policy = await findAndLoadPolicy(path, 'cpp', options);
        const issuesDataCamelCase = convertIssuesData(
          getIssuesResponse.data.result.issues_data,
        );
        const [issues, issuesData] = filterIgnoredIssues(
          resIssues,
          issuesDataCamelCase,
          policy,
        );

        const issuesMap: Map<string, Issue> = new Map();
        resIssues.forEach((i) => {
          issuesMap[i.issueId] = i;
        });

        const vulnerabilities: IssueData[] = [];
        for (const issuesDataKey in issuesDataCamelCase) {
          const issueData = issuesDataCamelCase[issuesDataKey];
          const pkgCoordinate = `${issuesMap[issuesDataKey].pkgName}@${issuesMap[issuesDataKey].pkgVersion}`;
          issueData.from = [pkgCoordinate];
          issueData.name = pkgCoordinate;
          issueData.packageManager = packageManager;
          vulnerabilities.push(issueData);
        }

        const dependencyCount = getIssuesResponse.data.result.dep_graph.graph.nodes.find(
          (graphNode) => {
            return graphNode.node_id === 'root-node';
          },
        )?.deps?.length;

        results.push({
          issues,
          issuesData,
          depGraphData: convertDepGraph(
            getIssuesResponse.data.result.dep_graph,
          ),
          depsFilePaths: getIssuesResponse.data.result.deps_file_paths,
          fileSignaturesDetails: convertFileSignatures(
            getIssuesResponse.data.result.file_signatures_details,
          ),
          vulnerabilities,
          path,
          dependencyCount,
          packageManager,
        });
      } catch (error) {
        const hasStatusCodeError = error.code >= 400 && error.code <= 500;
        if (hasStatusCodeError) {
          errors.push(error.message);
          continue;
        }
        const failedPath = path ? `in ${path}` : '.';
        errors.push(`Could not test dependencies ${failedPath}`);
      }
    }
  }
  spinner.clearAll();
  return [results, errors];
}

export async function resolveAndTestFactsLegacy(
  ecosystem: Ecosystem,
  scans: {
    [dir: string]: ScanResult[];
  },
  options: Options & PolicyOptions,
): Promise<[TestResult[], string[]]> {
  const results: any[] = [];
  const errors: string[] = [];
  const packageManager = 'Unmanaged (C/C++)';

  for (const [path, scanResults] of Object.entries(scans)) {
    await spinner(`Resolving and Testing fileSignatures in ${path}`);
    for (const scanResult of scanResults) {
      try {
        const res = await requestTestPollingToken(options, true, scanResult);
        if (scanResult.analytics) {
          extractAndApplyPluginAnalytics(scanResult.analytics, res.token);
        }
        const { maxAttempts, pollInterval } = res.pollingTask;
        const attemptsCount = 0;
        const response = await pollingTestWithTokenUntilDone(
          res.token,
          ecosystem,
          options,
          pollInterval,
          attemptsCount,
          maxAttempts,
        );

        const policy = await findAndLoadPolicy(path, 'cpp', options);
        const [issues, issuesData] = filterIgnoredIssues(
          response.issues,
          response.issuesData,
          policy,
        );

        const issuesMap: Map<string, Issue> = new Map();
        response.issues.forEach((i) => {
          issuesMap[i.issueId] = i;
        });

        const vulnerabilities: IssueData[] = [];
        for (const issuesDataKey in response.issuesData) {
          const issueData = response.issuesData[issuesDataKey];
          const pkgCoordinate = `${issuesMap[issuesDataKey].pkgName}@${issuesMap[issuesDataKey].pkgVersion}`;
          issueData.from = [pkgCoordinate];
          issueData.name = pkgCoordinate;
          issueData.packageManager = packageManager;
          vulnerabilities.push(issueData);
        }

        const dependencyCount = response?.depGraphData?.graph?.nodes?.find(
          (graphNode) => {
            return graphNode.nodeId === 'root-node';
          },
        )?.deps?.length;

        results.push({
          issues,
          issuesData,
          depGraphData: response?.depGraphData,
          depsFilePaths: response?.depsFilePaths,
          fileSignaturesDetails: response?.fileSignaturesDetails,
          vulnerabilities,
          path,
          dependencyCount,
          packageManager,
        });
      } catch (error) {
        const hasStatusCodeError = error.code >= 400 && error.code <= 500;
        if (hasStatusCodeError) {
          errors.push(error.message);
          continue;
        }
        const failedPath = path ? `in ${path}` : '.';
        errors.push(`Could not test dependencies ${failedPath}`);
      }
    }
  }
  spinner.clearAll();
  return [results, errors];
}
