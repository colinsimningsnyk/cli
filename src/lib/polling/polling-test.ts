import config from '../config';
import { isCI } from '../is-ci';
import { makeRequest } from '../request/promise';
import { Options } from '../types';

import { assembleQueryString } from '../snyk-test/common';
import { getAuthHeader } from '../api-token';
import {
  CreateDepGraphResponse,
  FileHashes,
  GetDepGraphResponse,
  GetIssuesResponse,
  IssuesRequestAttributes,
  ScanResult,
} from '../ecosystems/types';

import { ResolveAndTestFactsResponse } from './types';
import { delayNextStep, handleProcessingStatus } from './common';
import { TestDependenciesResult } from '../snyk-test/legacy';

export async function getIssues(
  issuesRequestAttributes: IssuesRequestAttributes,
): Promise<GetIssuesResponse> {
  const payload = {
    method: 'POST',
    url: `http://localhost:8079/rest/unmanaged_ecosystem/issues?version=2022-06-29~experimental`,
    json: true,
    headers: {
      'Content-Type': 'application/vnd.api+json',
      //'x-is-ci': isCI(),
      //authorization: getAuthHeader(),
    },
    body: issuesRequestAttributes,
    //qs: assembleQueryString(options),
  };

  const result = await makeRequest<GetIssuesResponse>(payload);
  return JSON.parse(result.toString());
}

export async function getDepGraph(
  hashes: FileHashes,
  id: string,
): Promise<GetDepGraphResponse> {
  const payload = {
    method: 'GET',
    url: `http://localhost:8079/rest/unmanaged_ecosystem/depgraphs/${id}?version=2022-05-23~experimental`,
    json: true,
    headers: {
      'Content-Type': 'application/vnd.api+json',
      //'x-is-ci': isCI(),
      //authorization: getAuthHeader(),
    },
    body: hashes,
    //qs: assembleQueryString(options),
  };

  const result = await makeRequest<GetDepGraphResponse>(payload);
  return JSON.parse(result.toString());
}

export async function createDepGraph(
  //options: Options,
  //isAsync: boolean, // TODO: delete this argument
  hashes: FileHashes,
): Promise<CreateDepGraphResponse> {
  const payload = {
    method: 'POST',
    url: `http://localhost:8079/rest/unmanaged_ecosystem/depgraphs?version=2022-05-23~experimental`,
    json: true,
    headers: {
      'Content-Type': 'application/vnd.api+json',
      //'x-is-ci': isCI(),
      //authorization: getAuthHeader(),
    },
    body: hashes,
    //qs: assembleQueryString(options),
  };
  const result = await makeRequest<CreateDepGraphResponse>(payload);
  return JSON.parse(result.toString());
}

export async function requestTestPollingToken(
  options: Options,
  isAsync: boolean,
  scanResult: ScanResult,
): Promise<ResolveAndTestFactsResponse> {
  const payload = {
    method: 'POST',
    url: `${config.API}/test-dependencies`,
    json: true,
    headers: {
      'x-is-ci': isCI(),
      authorization: getAuthHeader(),
    },
    body: {
      isAsync,
      scanResult,
    },
    qs: assembleQueryString(options),
  };
  return await makeRequest<ResolveAndTestFactsResponse>(payload);
}

export async function pollingTestWithTokenUntilDone(
  token: string,
  type: string,
  options: Options,
  pollInterval: number,
  attemptsCount: number,
  maxAttempts = Infinity,
): Promise<TestDependenciesResult> {
  const payload = {
    method: 'GET',
    url: `${config.API}/test-dependencies/${token}`,
    json: true,
    headers: {
      'x-is-ci': isCI(),
      authorization: getAuthHeader(),
    },
    qs: { ...assembleQueryString(options), type },
  };

  const response = await makeRequest<ResolveAndTestFactsResponse>(payload);

  handleProcessingStatus(response);

  if (response.result) {
    const {
      issues,
      issuesData,
      depGraphData,
      depsFilePaths,
      fileSignaturesDetails,
      vulnerabilities,
      path,
      dependencyCount,
      packageManager,
    } = response.result;
    return {
      issues,
      issuesData,
      depGraphData,
      depsFilePaths,
      fileSignaturesDetails,
      vulnerabilities,
      path,
      dependencyCount,
      packageManager,
    };
  }

  await delayNextStep(attemptsCount, maxAttempts, pollInterval);
  return await pollingTestWithTokenUntilDone(
    token,
    type,
    options,
    pollInterval,
    attemptsCount,
    maxAttempts,
  );
}
